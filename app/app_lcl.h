/*****************************************************************************
* Copyright (c) 2019, Cisco Systems, Inc.
* All rights reserved.

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

#ifndef LIBACVP_APP_LCL_H
#define LIBACVP_APP_LCL_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "acvp/acvp.h"

/*
 * MACROS
 */
#define DEFAULT_SERVER "127.0.0.1"
#define DEFAULT_PORT 443
#define DEFAULT_CA_CHAIN "certs/acvp-private-root-ca.crt.pem"
#define DEFAULT_CERT "certs/my-client-cert.pem"
#define DEFAULT_KEY "certs/my-client-key.pem"
#define JSON_FILENAME_LENGTH 24

typedef struct app_config {
    ACVP_LOG_LVL level;
    int sample;
    int dev;
    int json;
    char json_file[JSON_FILENAME_LENGTH + 1];

    /*
     * Algorithm Flags
     * 0 is off, 1 is on
     */
    int aes; int tdes;
    int hash; int cmac;
    int hmac;
    /* These require the fom */
#ifdef ACVP_NO_RUNTIME
    int dsa; int rsa;
    int drbg; int ecdsa;
    int kas_ecc; int kas_ffc;
#endif
#ifdef OPENSSL_KDF_SUPPORT
    int kdf;
#endif
} APP_CONFIG;


int ingest_cli(APP_CONFIG *cfg, int argc, char **argv);
ACVP_RESULT totp(char **token, int token_max);

int app_aes_handler_aead(ACVP_TEST_CASE *test_case);

#ifdef __cplusplus
}
#endif

#endif // LIBACVP_APP_LCL_H

