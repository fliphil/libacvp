/*****************************************************************************
* Copyright (c) 2019, Cisco Systems, Inc.
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without modification,
* are permitted provided that the following conditions are met:
*
* 1. Redistributions of source code must retain the above copyright notice,
*    this list of conditions and the following disclaimer.
*
* 2. Redistributions in binary form must reproduce the above copyright notice,
*    this list of conditions and the following disclaimer in the documentation
*    and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
* SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
* CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
* OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
* USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include "app_lcl.h"
#include "safe_lib.h"

/* This is a public domain base64 implementation written by WEI Zhicheng. */
enum { BASE64_OK = 0, BASE64_INVALID };

#define BASE64_ENCODE_OUT_SIZE(s)    (((s) + 2) / 3 * 4)
#define BASE64_DECODE_OUT_SIZE(s)    (((s)) / 4 * 3)

#define BASE64_PAD    '='

#define BASE64DE_FIRST    '+'
#define BASE64DE_LAST    'z'

/* ASCII order for BASE 64 decode, -1 in unused character */
static const signed char base64de[] = {
    /* '+', ',', '-', '.', '/', '0', '1', '2', */
    62, -1, -1, -1, 63, 52, 53, 54,

    /* '3', '4', '5', '6', '7', '8', '9', ':', */
    55, 56, 57, 58, 59, 60, 61, -1,

    /* ';', '<', '=', '>', '?', '@', 'A', 'B', */
    -1, -1, -1, -1, -1, -1, 0,  1,

    /* 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', */
    2,  3,  4,  5,  6,  7,  8,  9,

    /* 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', */
    10, 11, 12, 13, 14, 15, 16, 17,

    /* 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', */
    18, 19, 20, 21, 22, 23, 24, 25,

    /* '[', '\', ']', '^', '_', '`', 'a', 'b', */
    -1, -1, -1, -1, -1, -1, 26, 27,

    /* 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', */
    28, 29, 30, 31, 32, 33, 34, 35,

    /* 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', */
    36, 37, 38, 39, 40, 41, 42, 43,

    /* 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', */
    44, 45, 46, 47, 48, 49, 50, 51,
};

static unsigned int
base64_decode(const char *in, unsigned int inlen, unsigned char *out) {
    unsigned int i, j;

    for (i = j = 0; i < inlen; i++) {
        int c;
        int s = i % 4;             /* from 8/gcd(6, 8) */

        if (in[i] == '=')
            return j;

        if (in[i] < BASE64DE_FIRST || in[i] > BASE64DE_LAST ||
            (c = base64de[in[i] - BASE64DE_FIRST]) == -1)
            return 0;

        switch (s) {
        case 0:
            out[j] = ((unsigned int)c << 2) & 0xFF;
            continue;
        case 1:
            out[j++] += ((unsigned int)c >> 4) & 0x3;

            /* if not last char with padding */
            if (i < (inlen - 3) || in[inlen - 2] != '=')
                out[j] = ((unsigned int)c & 0xF) << 4;
            continue;
        case 2:
            out[j++] += ((unsigned int)c >> 2) & 0xF;

            /* if not last char with padding */
            if (i < (inlen - 2) || in[inlen - 1] != '=')
                out[j] =  ((unsigned int)c & 0x3) << 6;
            continue;
        case 3:
            out[j++] += (unsigned char)c;
        }
    }

    return j;
}

const int DIGITS_POWER[]
    //  0  1   2    3     4      5       6        7         8
    = { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000 };

#define T_LEN 8
#define MAX_LEN 512

static int hmac_totp(const char *key,
                     const unsigned char *msg,
                     char *hash,
                     int hash_max,
                     const EVP_MD *md,
                     unsigned int key_len) {
    int len = 0;
    unsigned char buff[MAX_LEN];
    HMAC_CTX *ctx;
    HMAC_CTX static_ctx;

    ctx = &static_ctx;
    HMAC_CTX_init(ctx);

    if (!HMAC_Init_ex(ctx, key, key_len, md, NULL)) goto end;
    if (!HMAC_Update(ctx, msg, T_LEN)) goto end;
    if (!HMAC_Final(ctx, buff, (unsigned int *)&len)) goto end;
    memcpy_s(hash, hash_max, buff, len);

end:
    HMAC_CTX_cleanup(ctx);

    return len;
}

ACVP_RESULT totp(char **token, int token_max) {
    char hash[MAX_LEN] = {0};
    int os, bin, otp;
    int md_len;
    char format[5];
    time_t t;
    unsigned char token_buff[T_LEN + 1] = {0};
    char *new_seed = calloc(ACVP_TOTP_TOKEN_MAX, sizeof(char));
    char *seed = NULL;
    int seed_len = 0;

    if (!new_seed) {
        printf("Failed to malloc new_seed\n");
        return ACVP_MALLOC_FAIL;
    }

    seed = getenv("ACV_TOTP_SEED");
    if (!seed) {
        printf("Failed to get TOTP seed\n");
        free(new_seed);
        return ACVP_TOTP_MISSING_SEED;
    }

    t = time(NULL);

    // RFC4226
    t = t / 30;
    token_buff[0] = (t >> T_LEN * 7) & 0xff;
    token_buff[1] = (t >> T_LEN * 6) & 0xff;
    token_buff[2] = (t >> T_LEN * 5) & 0xff;
    token_buff[3] = (t >> T_LEN * 4) & 0xff;
    token_buff[4] = (t >> T_LEN * 3) & 0xff;
    token_buff[5] = (t >> T_LEN * 2) & 0xff;
    token_buff[6] = (t >> T_LEN * 1) & 0xff;
    token_buff[7] = t & 0xff;

#define MAX_SEED_LEN 64
    seed_len = base64_decode(seed, strnlen_s(seed, MAX_SEED_LEN), (unsigned char *)new_seed);
    if (seed_len  == 0) {
        printf("Failed to decode TOTP seed\n");
        free(new_seed);
        return ACVP_TOTP_DECODE_FAIL;
    }


    // use passed hash function
    md_len = hmac_totp(new_seed, token_buff, hash, sizeof(hash), EVP_sha256(), seed_len);
    if (md_len == 0) {
        printf("Failed to create TOTP\n");
        free(new_seed);
        return ACVP_CRYPTO_MODULE_FAIL;
    }
    os = hash[(int)md_len - 1] & 0xf;

    bin = ((hash[os + 0] & 0x7f) << 24) |
          ((hash[os + 1] & 0xff) << 16) |
          ((hash[os + 2] & 0xff) <<  8) |
          ((hash[os + 3] & 0xff) <<  0);

    otp = bin % DIGITS_POWER[ACVP_TOTP_LENGTH];

    // generate format string like "%06d" to fix digits using 0
    sprintf(format, "%c0%ldd", '%', (long int)ACVP_TOTP_LENGTH);

    sprintf((char *)token_buff, format, otp);
    memcpy_s((char *)*token, token_max, token_buff, ACVP_TOTP_LENGTH);
    free(new_seed);
    return ACVP_SUCCESS;
}

