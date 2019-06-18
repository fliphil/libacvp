/*
 * Copyright (c) 2019, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */

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
#define DEFAULT_URI_PREFIX "/acvp/v1/"
#define JSON_FILENAME_LENGTH 128

typedef struct app_config {
    ACVP_LOG_LVL level;
    int sample;
    int json;
    int vector_req;
    int vector_rsp;
    int vector_upload;
    int kat;
    int fips_validation;
    char json_file[JSON_FILENAME_LENGTH + 1];
    char vector_req_file[JSON_FILENAME_LENGTH + 1];
    char vector_rsp_file[JSON_FILENAME_LENGTH + 1];
    char vector_upload_file[JSON_FILENAME_LENGTH + 1];
    char kat_file[JSON_FILENAME_LENGTH + 1];
    char validation_metadata_file[JSON_FILENAME_LENGTH + 1];

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
int app_setup_two_factor_auth(ACVP_CTX *ctx);

int app_aes_handler_aead(ACVP_TEST_CASE *test_case);

#ifdef __cplusplus
}
#endif

#endif // LIBACVP_APP_LCL_H

