/*
 * Copyright (c) 2019, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */

/*
 * This module is not part of libacvp.  Rather, it's a simple app that
 * demonstrates how to use libacvp. Software that use libacvp
 * will need to implement a similar module.
 *
 * It will default to 127.0.0.1 port 443 if no arguments are given.
 */
#include <stdio.h>
#include <stdlib.h>
#include <openssl/crypto.h>

#include "app_lcl.h"
#include "safe_lib.h"

static int enable_aes(ACVP_CTX *ctx);

char *server;
int port;
char *ca_chain_file;
char *cert_file;
char *key_file;
char *path_segment;
char *api_context;
char value[] = "same";

#define CHECK_ENABLE_CAP_RV(rv) \
    if (rv != ACVP_SUCCESS) { \
        printf("Failed to register capability with libacvp (rv=%d: %s)\n", rv, acvp_lookup_error_string(rv)); \
        goto end; \
    }

/*
 * Read the operational parameters from the various environment
 * variables.
 */
static void setup_session_parameters() {
    char *tmp;

    server = getenv("ACV_SERVER");
    if (!server) server = DEFAULT_SERVER;

    tmp = getenv("ACV_PORT");
    if (tmp) port = atoi(tmp);
    if (!port) port = DEFAULT_PORT;

    path_segment = getenv("ACV_URI_PREFIX");
    if (!path_segment) path_segment = DEFAULT_URI_PREFIX;

    api_context = getenv("ACV_API_CONTEXT");
    if (!api_context) api_context = "";

    ca_chain_file = getenv("ACV_CA_FILE");
    cert_file = getenv("ACV_CERT_FILE");
    key_file = getenv("ACV_KEY_FILE");

    printf("Using the following parameters:\n\n");
    printf("    ACV_SERVER:     %s\n", server);
    printf("    ACV_PORT:       %d\n", port);
    printf("    ACV_URI_PREFIX: %s\n", path_segment);
    if (ca_chain_file) printf("    ACV_CA_FILE:    %s\n", ca_chain_file);
    if (cert_file) printf("    ACV_CERT_FILE:  %s\n", cert_file);
    if (key_file) printf("    ACV_KEY_FILE:   %s\n\n", key_file);
}

/*
 * This is a minimal and rudimentary logging handler.
 * libacvp calls this function to for debugs, warnings,
 * and errors.
 */
static ACVP_RESULT progress(char *msg) {
    printf("%s", msg);
    return ACVP_SUCCESS;
}

static void app_cleanup(ACVP_CTX *ctx) {
    // Routines for libacvp
    acvp_cleanup(ctx);
}

int main(int argc, char **argv) {
    ACVP_RESULT rv = ACVP_SUCCESS;
    ACVP_CTX *ctx = NULL;
    APP_CONFIG cfg = { 0 };

    if (ingest_cli(&cfg, argc, argv)) {
        return 1;
    }

#ifdef ACVP_NO_RUNTIME
    fips_selftest_fail = 0;
    fips_mode = 0;
    fips_algtest_init_nofips();
#endif

     setup_session_parameters();

    /*
     * We begin the libacvp usage flow here.
     * First, we create a test session context.
     */
    rv = acvp_create_test_session(&ctx, &progress, cfg.level);
    if (rv != ACVP_SUCCESS) {
        printf("Failed to create ACVP context: %s\n", acvp_lookup_error_string(rv));
        goto end;
    }

    /*
     * Next we specify the ACVP server address
     */
    rv = acvp_set_server(ctx, server, port);
    if (rv != ACVP_SUCCESS) {
        printf("Failed to set server/port\n");
        goto end;
    }

    /*
     * Set the api context prefix if needed
     */
    rv = acvp_set_api_context(ctx, api_context);
    if (rv != ACVP_SUCCESS) {
        printf("Failed to set URI prefix\n");
        goto end;
    }

    /*
     * Set the path segment prefix if needed
     */
    rv = acvp_set_path_segment(ctx, path_segment);
    if (rv != ACVP_SUCCESS) {
        printf("Failed to set URI prefix\n");
        goto end;
    }

#if 0
    if (ca_chain_file) {
        /*
         * Next we provide the CA certs to be used by libacvp
         * to verify the ACVP TLS certificate.
         */
        rv = acvp_set_cacerts(ctx, ca_chain_file);
        if (rv != ACVP_SUCCESS) {
            printf("Failed to set CA certs\n");
            goto end;
        }
    }

    if (cert_file && key_file) {
        /*
         * Specify the certificate and private key the client should used
         * for TLS client auth.
         */
        rv = acvp_set_certkey(ctx, cert_file, key_file);
        if (rv != ACVP_SUCCESS) {
            printf("Failed to set TLS cert/key\n");
            goto end;
        }
    }

    /*
     * Setup the Two-factor authentication
     * This may or may not be turned on...
     */
    if (app_setup_two_factor_auth(ctx)) {
        goto end;
    }
#endif

    if (cfg.sample) {
        acvp_mark_as_sample(ctx);
    }

    if (cfg.vector_req && !cfg.vector_rsp) {
        acvp_mark_as_request_only(ctx, cfg.vector_req_file);
    }

    if (!cfg.vector_req && cfg.vector_rsp) {
        printf("Offline vector processing requires both options, --vector_req and --vector_rsp\n");
        goto end;
    }


    if (cfg.json) {
        /*
         * Using a JSON to register allows us to skip the
         * "acvp_enable_*" API calls... could reduce the
         * size of this file if you choose to use this capability.
         */
        rv = acvp_set_json_filename(ctx, cfg.json_file);
        if (rv != ACVP_SUCCESS) {
            printf("Failed to set json file within ACVP ctx (rv=%d)\n", rv);
            goto end;
        }
    } else {
        /*
         * We need to register all the crypto module capabilities that will be
         * validated. Each has their own method for readability.
         */
        if (cfg.aes) {
            if (enable_aes(ctx)) goto end;
        }
    }

    if (cfg.kat) {
       rv = acvp_load_kat_filename(ctx, cfg.kat_file);
       goto end;
    }

    if (cfg.vector_req && cfg.vector_rsp) {
       rv = acvp_run_vectors_from_file(ctx, cfg.vector_req_file, cfg.vector_rsp_file);
       goto end;
    }

    if (cfg.vector_upload) {
       rv = acvp_upload_vectors_from_file(ctx, cfg.vector_upload_file);
       goto end;
    }

    if (cfg.fips_validation) {
        unsigned int module_id = 1, oe_id = 1;

        /*
         * Provide the metadata needed for a FIPS validation.
         */
        rv = acvp_oe_ingest_metadata(ctx, cfg.validation_metadata_file);
        if (rv != ACVP_SUCCESS) {
            printf("Failed to read validation_metadata_file\n");
            goto end;
        }

        /*
         * Tell the library which Module and Operating Environment to use
         * when doing the FIPS validation.
         */
        rv = acvp_oe_set_fips_validation_metadata(ctx, module_id, oe_id);
        if (rv != ACVP_SUCCESS) {
            printf("Failed to set metadata for FIPS validation\n");
            goto end;
        }
    }

    /*
     * Run the test session.
     * Perform a FIPS validation on this test session if specified.
     */
    acvp_run(ctx, cfg.fips_validation);

end:
    /*
     * Free all memory associated with
     * both the application and libacvp.
     */
    app_cleanup(ctx);

    return rv;
}

static int enable_aes(ACVP_CTX *ctx) {
    ACVP_RESULT rv = ACVP_SUCCESS;

    /*
     * Enable AES_GCM
     */
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_GCM_SIV, &app_aes_handler_aead);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_AES_GCM_SIV, ACVP_PREREQ_AES, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_set_prereq(ctx, ACVP_AES_GCM_SIV, ACVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM_SIV, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM_SIV, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_NA);
    CHECK_ENABLE_CAP_RV(rv);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM_SIV, ACVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM_SIV, ACVP_SYM_CIPH_TAGLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM_SIV, ACVP_SYM_CIPH_IVLEN, 96);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM_SIV, ACVP_SYM_CIPH_PTLEN, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM_SIV, ACVP_SYM_CIPH_PTLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM_SIV, ACVP_SYM_CIPH_PTLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM_SIV, ACVP_SYM_CIPH_AADLEN, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM_SIV, ACVP_SYM_CIPH_AADLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);

end:

    return rv;
}

