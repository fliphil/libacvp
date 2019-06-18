/*
 * Copyright (c) 2019, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */


#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/aead.h>
#include "app_lcl.h"
#include "safe_mem_lib.h"


#define GCM_SIV_TAG_BYTE_LEN 16

static int gcm(ACVP_SYM_CIPHER_TC *tc) {
    EVP_CIPHER_CTX *cipher_ctx = NULL;
    const EVP_CIPHER *cipher;
    unsigned char iv_fixed[4] = { 1, 2, 3, 4 };
    int rc = 1, ret = 0;

    switch (tc->key_len) {
    case 128:
        cipher = EVP_aes_128_gcm();
        break;
    case 192:
        cipher = EVP_aes_192_gcm();
        break;
    case 256:
        cipher = EVP_aes_256_gcm();
        break;
    default:
        printf("Unsupported AES-GCM key length\n");
        return 1;
    }

    /* Begin encrypt code section */
    cipher_ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(cipher_ctx);

    if (tc->direction == ACVP_SYM_CIPH_DIR_ENCRYPT) {
        EVP_CipherInit(cipher_ctx, cipher, NULL, NULL, 1);
        EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_SET_IVLEN, tc->iv_len, 0);
        EVP_CipherInit(cipher_ctx, NULL, tc->key, NULL, 1);

        EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_SET_IV_FIXED, 4, iv_fixed);
        if (!EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_IV_GEN, tc->iv_len, tc->iv)) {
            printf("acvp_aes_encrypt: iv gen error\n");
            goto end;
        }
        if (tc->aad_len) {
            EVP_Cipher(cipher_ctx, NULL, tc->aad, tc->aad_len);
        }
        EVP_Cipher(cipher_ctx, tc->ct, tc->pt, tc->pt_len);
        EVP_Cipher(cipher_ctx, NULL, NULL, 0);
        EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_GET_TAG, tc->tag_len, tc->tag);
    } else if (tc->direction == ACVP_SYM_CIPH_DIR_DECRYPT) {
        EVP_CipherInit_ex(cipher_ctx, cipher, NULL, tc->key, NULL, 0);
        EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_SET_IVLEN, tc->iv_len, 0);
        EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_SET_IV_FIXED, -1, tc->iv);
        if (!EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_IV_GEN, tc->iv_len, tc->iv)) {
            printf("\nFailed to set IV");
            goto end;
        }
        if (tc->aad_len) {
            /*
             * Set dummy tag before processing AAD.  Otherwise the AAD can
             * not be processed.
             */
            EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_SET_TAG, tc->tag_len, tc->tag);
            EVP_Cipher(cipher_ctx, NULL, tc->aad, tc->aad_len);
        }
        /*
         * Set the tag when decrypting
         */
        EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_SET_TAG, tc->tag_len, tc->tag);

        /*
         * Decrypt the CT
         */
        EVP_Cipher(cipher_ctx, tc->pt, tc->ct, tc->ct_len);
        /*
         * Check the tag
         */
        ret = EVP_Cipher(cipher_ctx, NULL, NULL, 0);
        if (ret) goto end;
    }

    /* Success */
    rc = 0;

end:
    /* Cleanup */
    if (cipher_ctx) EVP_CIPHER_CTX_free(cipher_ctx);

    return rc;
}

static int gcm_siv(ACVP_SYM_CIPHER_TC *tc) {
    EVP_AEAD_CTX *aead_ctx = NULL;
    const EVP_AEAD *aead;
    int rc = 1, ret = 0;

    switch (tc->key_len) {
    case 128:
        aead = EVP_aead_aes_128_gcm_siv();;
        break;
    case 256:
        aead = EVP_aead_aes_256_gcm_siv();;
        break;
    default:
        printf("Unsupported AES-GCM key length\n");
        return 1;
    }

    /* Begin encrypt code section */
    aead_ctx = EVP_AEAD_CTX_new(aead, tc->key, tc->key_len / 8, tc->tag_len);

    if (tc->direction == ACVP_SYM_CIPH_DIR_ENCRYPT) {
        size_t ct_len = 0;

        ret = EVP_AEAD_CTX_seal(aead_ctx, tc->ct, &ct_len, tc->ct_max,
                                tc->iv, tc->iv_len, tc->pt, tc->pt_len,
                                tc->aad, tc->aad_len);
        tc->ct_len = (unsigned int)ct_len;

        if (ret == 0) {
            printf("EVP_AEAD_CTX_deal failed\n");
            goto end;
        }

        /* Grab the TAG */
        memcpy_s(tc->tag, tc->tag_max, tc->ct + tc->pt_len, GCM_SIV_TAG_BYTE_LEN);
        /* Don't include the tag in the ct field */
        tc->ct_len -= GCM_SIV_TAG_BYTE_LEN;
    } else if (tc->direction == ACVP_SYM_CIPH_DIR_DECRYPT) {
        size_t pt_len = 0;

        /* Append the TAG */
#if 0
        memcpy_s(tc->ct + tc->ct_len, tc->ct_max - tc->ct_len, tc->tag, GCM_SIV_TAG_BYTE_LEN);
        /* Add the tag length in the ct_len field */
        tc->ct_len += GCM_SIV_TAG_BYTE_LEN;
#endif
        ret = EVP_AEAD_CTX_open(aead_ctx, tc->pt, &pt_len, tc->pt_max,
                                tc->iv, tc->iv_len, tc->ct, tc->ct_len,
                                tc->aad, tc->aad_len);
        tc->pt_len = (unsigned int)pt_len;

        if (ret == 0) {
            printf("EVP_AEAD_CTX_open failed\n");
            goto end;
        }
    }

    /* Success */
    rc = 0;

end:
    /* Cleanup */
    if (aead_ctx) EVP_AEAD_CTX_free(aead_ctx);

    return rc;
}

/*
 * This fuction is invoked by libacvp when an AES crypto
 * operation is needed from the crypto module being
 * validated.  This is a callback provided to libacvp when
 * acvp_enable_capability() is invoked to register the
 * AES-GCM capabilitiy with libacvp.  libacvp will in turn
 * invoke this function when it needs to process an AES-GCM
 * test case.
 */
int app_aes_handler_aead(ACVP_TEST_CASE *test_case) {
    ACVP_SYM_CIPHER_TC *tc = NULL;
    int ret = 0;

    if (!test_case) {
        return 1;
    }

    /* Resolve the union to the symmetric struct */
    tc = test_case->tc.symmetric;

    if (tc->direction != ACVP_SYM_CIPH_DIR_ENCRYPT
        && tc->direction != ACVP_SYM_CIPH_DIR_DECRYPT) {
        printf("Unsupported direction\n");
        return 1;
    }

    /* Validate key length and assign OpenSSL EVP cipher */
    switch (tc->cipher) {
    case ACVP_AES_GCM:
        ret = gcm(tc);
        break;
    case ACVP_AES_GCM_SIV:
        ret = gcm_siv(tc);
        break;
    default:
        printf("Error: Unsupported AES AEAD mode requested by ACVP server\n");
        return 1;
    }

    return ret;
}

