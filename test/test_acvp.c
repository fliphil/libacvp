/** @file */
/*
 * Copyright (c) 2019, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */


#include "ut_common.h"
#include "acvp_lcl.h"

ACVP_CTX *ctx;
static char filename[] = "filename";
static char value[] = "same";
char *test_server = "demo.acvts.nist.gov";
char *api_context = "acvp/";
char *path_segment = "acvp/v1/";
char *uri = "login";
int port = 443;
ACVP_RESULT rv;

static void setup(void) {
    setup_empty_ctx(&ctx);
}

static void setup_full_ctx(void) {
    setup_empty_ctx(&ctx);
    
    rv = acvp_cap_sym_cipher_enable(ctx, ACVP_AES_GCM, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_AES_GCM, ACVP_PREREQ_AES, value);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_AES_GCM, ACVP_PREREQ_DRBG, value);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PARM_DIR, ACVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PARM_KO, ACVP_SYM_CIPH_KO_NA);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PARM_IVGEN_SRC, ACVP_SYM_CIPH_IVGEN_SRC_INT);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PARM_IVGEN_MODE, ACVP_SYM_CIPH_IVGEN_MODE_821);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_KEYLEN, 128);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_TAGLEN, 96);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_IVLEN, 96);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_PTLEN, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_sym_cipher_set_parm(ctx, ACVP_AES_GCM, ACVP_SYM_CIPH_AADLEN, 0);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv = acvp_cap_hash_enable(ctx, ACVP_HASH_SHA1, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_cmac_enable(ctx, ACVP_CMAC_AES, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_AES, ACVP_CMAC_MACLEN, 128);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_AES, ACVP_CMAC_KEYLEN, 128);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_cmac_set_parm(ctx, ACVP_CMAC_AES, ACVP_CMAC_DIRECTION_GEN, 1);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_hmac_enable(ctx, ACVP_HMAC_SHA1, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv = acvp_cap_kdf135_tls_enable(ctx, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_TLS, ACVP_PREREQ_SHA, value);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_KDF135_TLS, ACVP_PREREQ_HMAC, value);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kdf135_tls_set_parm(ctx, ACVP_KDF135_TLS, ACVP_KDF135_TLS12, ACVP_SHA256 | ACVP_SHA384 | ACVP_SHA512);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv = acvp_cap_kas_ecc_enable(ctx, ACVP_KAS_ECC_CDH, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_prereq(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_PREREQ_ECDSA, value);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_FUNCTION, ACVP_KAS_ECC_FUNC_PARTIAL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ecc_set_parm(ctx, ACVP_KAS_ECC_CDH, ACVP_KAS_ECC_MODE_CDH, ACVP_KAS_ECC_CURVE, ACVP_EC_CURVE_P224);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv = acvp_cap_kas_ffc_enable(ctx, ACVP_KAS_FFC_COMP, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_prereq(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_PREREQ_HMAC, value);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_parm(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_FUNCTION, ACVP_KAS_FFC_FUNC_DPGEN);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_parm(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_FUNCTION, ACVP_KAS_FFC_FUNC_DPVAL);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_scheme(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_DH_EPHEMERAL,  ACVP_KAS_FFC_ROLE, ACVP_KAS_FFC_ROLE_INITIATOR);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_scheme(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_DH_EPHEMERAL,  ACVP_KAS_FFC_KDF, ACVP_KAS_FFC_NOKDFNOKC);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_kas_ffc_set_scheme(ctx, ACVP_KAS_FFC_COMP, ACVP_KAS_FFC_MODE_COMPONENT, ACVP_KAS_FFC_DH_EPHEMERAL, ACVP_KAS_FFC_FB, ACVP_SHA224);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv = acvp_cap_dsa_enable(ctx, ACVP_DSA_PQGGEN, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_DSA_PQGGEN, ACVP_PREREQ_SHA, value);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_GENPQ, ACVP_DSA_PROBABLE);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_LN2048_224, ACVP_SHA224);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_dsa_set_parm(ctx, ACVP_DSA_PQGGEN, ACVP_DSA_MODE_PQGGEN, ACVP_DSA_GENG, ACVP_DSA_CANONICAL);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv = acvp_cap_rsa_sig_enable(ctx, ACVP_RSA_SIGGEN, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_siggen_set_type(ctx, ACVP_RSA_SIG_TYPE_X931);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_rsa_siggen_set_mod_parm(ctx, ACVP_RSA_SIG_TYPE_X931, 2048, ACVP_SHA256, 0);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv = acvp_cap_ecdsa_enable(ctx, ACVP_ECDSA_KEYGEN, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_ECDSA_KEYGEN, ACVP_PREREQ_SHA, value);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_ECDSA_KEYGEN, ACVP_PREREQ_DRBG, value);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_CURVE, ACVP_EC_CURVE_P224);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_ecdsa_set_parm(ctx, ACVP_ECDSA_KEYGEN, ACVP_ECDSA_SECRET_GEN, ACVP_ECDSA_SECRET_GEN_TEST_CAND);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv = acvp_cap_drbg_enable(ctx, ACVP_HASHDRBG, &dummy_handler_success);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_drbg_set_parm(ctx, ACVP_HASHDRBG, ACVP_DRBG_SHA_1,  ACVP_DRBG_DER_FUNC_ENABLED, 0);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_cap_set_prereq(ctx, ACVP_HASHDRBG, ACVP_PREREQ_SHA, value);
    cr_assert(rv == ACVP_SUCCESS);

}

static void teardown(void) {
    if (ctx) teardown_ctx(&ctx);
}

static ACVP_RESULT dummy_totp_success(char **token, int token_max) {
    strncpy(*token, "test", 4);
    return ACVP_SUCCESS;
}

static ACVP_RESULT dummy_totp_overflow(char **token, int token_max) {
    memset(*token, 'a', 129);
    return ACVP_SUCCESS;
}

/*
 * This test sets up a new test session with good params
 */
Test(CREATE_CTX, good) {
    rv = acvp_create_test_session(&ctx, &progress, ACVP_LOG_LVL_STATUS);
    cr_assert(rv == ACVP_SUCCESS);
    teardown_ctx(&ctx);
    ctx = NULL;
    
    rv = acvp_create_test_session(&ctx, &progress, ACVP_LOG_LVL_ERR);
    cr_assert(rv == ACVP_SUCCESS);
    teardown_ctx(&ctx);
    ctx = NULL;
    
    rv = acvp_create_test_session(&ctx, &progress, ACVP_LOG_LVL_WARN);
    cr_assert(rv == ACVP_SUCCESS);
    teardown_ctx(&ctx);
    ctx = NULL;
    
    rv = acvp_create_test_session(&ctx, &progress, ACVP_LOG_LVL_INFO);
    cr_assert(rv == ACVP_SUCCESS);
    teardown_ctx(&ctx);
    ctx = NULL;
    
    rv = acvp_create_test_session(&ctx, &progress, ACVP_LOG_LVL_VERBOSE);
    cr_assert(rv == ACVP_SUCCESS);
    teardown_ctx(&ctx);
    ctx = NULL;

    rv = acvp_create_test_session(&ctx, &progress, 0);
    cr_assert(rv == ACVP_SUCCESS);
    teardown_ctx(&ctx);
    ctx = NULL;

    rv = acvp_create_test_session(&ctx, NULL, ACVP_LOG_LVL_VERBOSE);
    cr_assert(rv == ACVP_SUCCESS);
    teardown_ctx(&ctx);
    ctx = NULL;
}

/*
 * This test sets up a new test session with non-null ctx
 */
Test(CREATE_CTX, dup_ctx) {
    ACVP_CTX *ctx = NULL;

    rv = acvp_create_test_session(&ctx, &progress, ACVP_LOG_LVL_VERBOSE);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv = acvp_create_test_session(&ctx, &progress, ACVP_LOG_LVL_VERBOSE);
    cr_assert(rv == ACVP_DUPLICATE_CTX);
    
    teardown_ctx(&ctx);
}


/*
 * This test sets up a new test session with null ctx
 */
Test(CREATE_CTX, null_ctx) {
    rv = acvp_create_test_session(NULL, &progress, ACVP_LOG_LVL_STATUS);
    cr_assert(rv == ACVP_INVALID_ARG);
    cr_assert(ctx == NULL);
}

/*
 * This test sets 2fa cb
 */
Test(SET_SESSION_PARAMS, good_2fa, .init = setup, .fini = teardown) {
    rv = acvp_set_2fa_callback(ctx, &dummy_totp_success);
    cr_assert(rv == ACVP_SUCCESS);
}

/*
 * This test sets 2fa cb with null params
 */
Test(SET_SESSION_PARAMS, null_params_2fa, .init = setup, .fini = teardown) {
    rv = acvp_set_2fa_callback(ctx, NULL);
    cr_assert(rv == ACVP_MISSING_ARG);
    
    rv = acvp_set_2fa_callback(NULL, &dummy_totp_success);
    cr_assert(rv == ACVP_NO_CTX);
}

/*
 * This test sets json filename
 */
Test(SET_SESSION_PARAMS, set_input_json_good, .init = setup, .fini = teardown) {
    rv = acvp_set_json_filename(ctx, filename);
    cr_assert(rv == ACVP_SUCCESS);
}

/*
 * This test sets json filename - null params
 */
Test(SET_SESSION_PARAMS, set_input_json_null_params, .init = setup, .fini = teardown) {
    rv = acvp_set_json_filename(NULL, filename);
    cr_assert(rv == ACVP_NO_CTX);

    rv = acvp_set_json_filename(ctx, NULL);
    cr_assert(rv == ACVP_MISSING_ARG);
}

/*
 * This test sets server info
 */
Test(SET_SESSION_PARAMS, set_server_good, .init = setup, .fini = teardown) {
    rv = acvp_set_server(ctx, "for test", 1111);
    cr_assert(rv == ACVP_SUCCESS);
}

/*
 * This test sets server info with NULL params
 */
Test(SET_SESSION_PARAMS, set_server_null_params, .init = setup, .fini = teardown) {
    rv = acvp_set_server(NULL, "for test", 1111);
    cr_assert(rv == ACVP_NO_CTX);
    rv = acvp_set_server(ctx, NULL, 1111);
    cr_assert(rv == ACVP_INVALID_ARG);
    rv = acvp_set_server(ctx, "for test", -1);
    cr_assert(rv == ACVP_INVALID_ARG);
}

/*
 * This test sets server info with long params
 */
Test(SET_SESSION_PARAMS, set_server_overflow, .init = setup, .fini = teardown) {
    char long_str[1000];
    int i;
    for (i = 0; i < 999; i++) {
        long_str[i] = 'a';
    }
    long_str[999] = '\0';
    
    rv = acvp_set_server(ctx, long_str, -1);
    cr_assert(rv == ACVP_INVALID_ARG);
}

/*
 * This test sets path_segment info
 */
Test(SET_SESSION_PARAMS, set_path_segment_good, .init = setup, .fini = teardown) {
    rv = acvp_set_path_segment(ctx, "for test");
    cr_assert(rv == ACVP_SUCCESS);
}

/*
 * This test sets path_segment info with NULL params
 */
Test(SET_SESSION_PARAMS, set_path_segment_null_params, .init = setup, .fini = teardown) {
    rv = acvp_set_path_segment(NULL, "for test");
    cr_assert(rv == ACVP_NO_CTX);
    rv = acvp_set_path_segment(ctx, NULL);
    cr_assert(rv == ACVP_INVALID_ARG);
}

/*
 * This test sets path_segment info with long params
 */
Test(SET_SESSION_PARAMS, set_path_segment_overflow, .init = setup, .fini = teardown) {
    char long_str[1000];
    int i;
    for (i = 0; i < 999; i++) {
        long_str[i] = 'a';
    }
    long_str[999] = '\0';
    
    rv = acvp_set_path_segment(ctx, long_str);
    cr_assert(rv == ACVP_INVALID_ARG);
}

/*
 * This test sets cacerts info
 */
Test(SET_SESSION_PARAMS, set_cacerts_good, .init = setup, .fini = teardown) {
    rv = acvp_set_cacerts(ctx, "for test");
    cr_assert(rv == ACVP_SUCCESS);
}

/*
 * This test sets cacerts info with NULL params
 */
Test(SET_SESSION_PARAMS, set_cacerts_null_params, .init = setup, .fini = teardown) {
    rv = acvp_set_cacerts(NULL, "for test");
    cr_assert(rv == ACVP_NO_CTX);
    rv = acvp_set_cacerts(ctx, NULL);
    cr_assert(rv == ACVP_MISSING_ARG);
}

/*
 * This test sets cacerts info with long params
 */
Test(SET_SESSION_PARAMS, set_cacerts_overflow, .init = setup, .fini = teardown) {
    char long_str[1000];
    int i;
    for (i = 0; i < 999; i++) {
        long_str[i] = 'a';
    }
    long_str[999] = '\0';
    
    rv = acvp_set_cacerts(ctx, long_str);
    cr_assert(rv == ACVP_INVALID_ARG);
}

/*
 * This test sets cert_key info
 */
Test(SET_SESSION_PARAMS, set_cert_key_good, .init = setup, .fini = teardown) {
    rv = acvp_set_certkey(ctx, "for test", "for test");
    cr_assert(rv == ACVP_SUCCESS);
}

/*
 * This test sets cert_key info with NULL params
 */
Test(SET_SESSION_PARAMS, set_cert_key_null_params, .init = setup, .fini = teardown) {
    rv = acvp_set_certkey(NULL, "for test", "for test");
    cr_assert(rv == ACVP_NO_CTX);
    rv = acvp_set_certkey(ctx, NULL, "for test");
    cr_assert(rv == ACVP_MISSING_ARG);
    rv = acvp_set_certkey(ctx, "for test", NULL);
    cr_assert(rv == ACVP_MISSING_ARG);
}

/*
 * This test sets cert_key info with long params
 */
Test(SET_SESSION_PARAMS, set_cert_key_overflow, .init = setup, .fini = teardown) {
    char long_str[1000];
    int i;
    for (i = 0; i < 999; i++) {
        long_str[i] = 'a';
    }
    long_str[999] = '\0';
    
    rv = acvp_set_certkey(ctx, long_str, "for test");
    cr_assert(rv == ACVP_INVALID_ARG);
    rv = acvp_set_certkey(ctx, "for test", long_str);
    cr_assert(rv == ACVP_INVALID_ARG);
}

/*
 * This test marks as sample
 */
Test(SET_SESSION_PARAMS, mark_as_sample_good, .init = setup, .fini = teardown) {
    rv = acvp_mark_as_sample(ctx);
    cr_assert(rv == ACVP_SUCCESS);
}

/*
 * This test marks as sample with null ctx
 */
Test(SET_SESSION_PARAMS, mark_as_sample_null_ctx, .init = setup, .fini = teardown) {
    rv = acvp_mark_as_sample(NULL);
    cr_assert(rv == ACVP_NO_CTX);
}

/*
 * This test frees ctx
 */
Test(FREE_TEST_SESSION, good, .init = setup) {
    rv = acvp_free_test_session(ctx);
    cr_assert(rv == ACVP_SUCCESS);
}

/*
 * This test frees ctx - should still succeed
 */
Test(FREE_TEST_SESSION, null_ctx, .init = setup) {
    free(ctx);    /* it got allocated in setup */
    ctx = NULL;
    rv = acvp_free_test_session(ctx);
    cr_assert(rv == ACVP_SUCCESS);
}

/*
 * This test frees ctx - should still succeed
 */
Test(FREE_TEST_SESSION, good_full, .init = setup_full_ctx) {
    rv = acvp_free_test_session(ctx);
    cr_assert(rv == ACVP_SUCCESS);
}

/*
 * Calls run with missing path segment
 */
Test(RUN, missing_path, .init = setup_full_ctx, .fini = teardown) {
    rv = acvp_set_server(ctx, test_server, port);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv = acvp_set_api_context(ctx, api_context);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv = acvp_set_server(ctx, test_server, port);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv = acvp_set_2fa_callback(ctx, &totp);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_run(ctx, 0);
    cr_assert(rv == ACVP_MISSING_ARG);
}

/*
 * Calls run with good values
 * transport fail is exptected - we made it through the register
 * API successfully to try to send the registration. that part
 * will fail - no actual connection to server here.
 * This expects ACVP_TRANSPORT_FAIL because refresh sends
 * but we don't receive HTTP_OK
 */
Test(RUN, good, .init = setup_full_ctx, .fini = teardown) {
    rv = acvp_set_server(ctx, test_server, port);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv = acvp_set_api_context(ctx, api_context);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv = acvp_set_path_segment(ctx, path_segment);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv = acvp_set_server(ctx, test_server, port);
    cr_assert(rv == ACVP_SUCCESS);
    
    rv = acvp_set_2fa_callback(ctx, &totp);
    cr_assert(rv == ACVP_SUCCESS);

    rv = acvp_run(ctx, 0);
    cr_assert(rv == ACVP_TRANSPORT_FAIL);
}

/*
 * This calls run with an overflow totp that will get
 * triggered in build_login
 */
Test(RUN, bad_totp_cb, .init = setup_full_ctx, .fini = teardown) {
    rv = acvp_set_2fa_callback(ctx, &dummy_totp_overflow);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_run(ctx, 0);
    cr_assert(rv == ACVP_INVALID_ARG);
}

/*
 * This calls run without adding totp callback - we expect
 * transport fail because we should make it through the rest
 * of the register api, but fail because we aren't going to be
 * able to successfully connect to NIST
 */
Test(RUN, good_without_totp, .init = setup_full_ctx, .fini = teardown) {
    rv = acvp_run(ctx, 0);
    cr_assert(rv == ACVP_MISSING_ARG);
}

/*
 * Run with null ctx
 */
Test(RUN, null_ctx, .fini = teardown) {
    rv = acvp_run(NULL, 0);
    cr_assert(rv == ACVP_NO_CTX);
}

/*
 * Check test results with empty ctx
 */
Test(CHECK_RESULTS, no_vs_list, .init = setup, .fini = teardown) {
    rv = acvp_check_test_results(ctx);
    cr_assert(rv == ACVP_MISSING_ARG);
}

/*
 * Process tests with full ctx - should return ACVP_MISSING_ARG for
 * now, at least until mock server is set up (because we didn't receive
 * any vectors to load in)
 */
Test(PROCESS_TESTS, good, .init = setup_full_ctx, .fini = teardown) {
    rv = acvp_process_tests(ctx);
    cr_assert(rv == ACVP_MISSING_ARG);
}

/*
 * process tests with null ctx
 */
Test(PROCESS_TESTS, null_ctx, .fini = teardown) {
    rv = acvp_process_tests(NULL);
    cr_assert(rv == ACVP_NO_CTX);
}

/*
 * process tests with empty ctx
 */
Test(PROCESS_TESTS, no_vs_list, .init = setup, .fini = teardown) {
    rv = acvp_process_tests(ctx);
    cr_assert(rv == ACVP_MISSING_ARG);
}

Test(GET_LIBRARY_VERSION, good) {
    char *version = acvp_version();
    cr_assert(version != NULL);
    cr_assert(strlen(version) > 0);
}

Test(GET_PROTOCOL_VERSION, good) {
    char *version = acvp_protocol_version();
    cr_assert(version != NULL);
    cr_assert(strlen(version) > 0);
}

/*
 * calls acvp_refresh with good params, didn't add totp callback
 */
Test(REFRESH, good_without_totp, .init = setup_full_ctx, .fini = teardown) {
    rv = acvp_set_server(ctx, test_server, port);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_set_path_segment(ctx, path_segment);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_refresh(ctx);
    cr_assert(rv == ACVP_TRANSPORT_FAIL);
}

/*
 * calls acvp_refresh with null ctx
 */
Test(REFRESH, null_ctx, .fini = teardown) {
    rv = acvp_refresh(NULL);
    cr_assert(rv == ACVP_NO_CTX);
}

/*
 * calls acvp_refresh with good params
 * This expects ACVP_TRANSPORT_FAIL because refresh sends
 * but we don't receive HTTP_OK
 */
Test(REFRESH, good_with_totp, .init = setup_full_ctx, .fini = teardown) {
    rv = acvp_set_server(ctx, test_server, port);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_set_api_context(ctx, api_context);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_set_path_segment(ctx, path_segment);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_set_2fa_callback(ctx, &totp);
    cr_assert(rv == ACVP_SUCCESS);
    rv = acvp_refresh(ctx);
    cr_assert(rv == ACVP_TRANSPORT_FAIL);
}

/*
 * Good tests - should still pass even if ctx is null
 */
Test(FREE_CTX, good, .init = setup_full_ctx) {
    rv = acvp_free_test_session(ctx);
    cr_assert(rv == ACVP_SUCCESS);
    ctx = NULL;
    rv = acvp_free_test_session(ctx);
    cr_assert(rv == ACVP_SUCCESS);
}
