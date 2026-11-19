/*
 * Copyright (C) 2026, PureDarwin contributors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

// pd interim LLM-written code, experimental and not secure: unaudited, unfuzzed, no side-channel review
// ccrsa_pd_security.c - the rsa API Security.framework's private copy uses: the public operations over the kext's
// Montgomery arithmetic, RSAPublicKey import (RFC 8017 A.1.1), and the private operations, which fail until they
// are written
#include <stdlib.h>
#include <corecrypto/ccrsa.h>
#include <corecrypto/cczp_priv.h>
#include <corecrypto/ccder.h>

size_t ccrsa_block_size(ccrsa_pub_ctx_t pub)
{
    return (ccn_bitlen(ccrsa_ctx_n(pub), ccrsa_ctx_m(pub)) + 7) / 8;
}

// rsaep / rsavp1, RFC 8017 5.1.1 and 5.2.2: the input has to be below the modulus
cc_error_t ccrsa_pub_crypt(ccrsa_pub_ctx_t pub, cc_unit *out, const cc_unit *in)
{
    cc_size n = ccrsa_ctx_n(pub);
    cc_unit *ws;

    if (ccn_cmp(n, in, ccrsa_ctx_m(pub)) >= 0)
        return CCERR_PARAMETER;
    ws = calloc(3 * n + 2, sizeof(cc_unit));
    if (ws == NULL)
        return CCERR_MEMORY;
    ccn_mont_powmod(n, out, in, n, ccrsa_ctx_e(pub), ccrsa_ctx_m(pub), *ccrsa_ctx_m0inv(pub), ccrsa_ctx_mr2(pub),
        ws);
    cc_clear((3 * n + 2) * sizeof(cc_unit), ws);
    free(ws);
    return CCERR_OK;
}

// RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }: the two integers' value octets
static int pub_parts(size_t inlen, const uint8_t *der, const uint8_t **m, size_t *m_len, const uint8_t **e,
    size_t *e_len)
{
    const uint8_t *end = der + inlen, *body_end;
    const uint8_t *p = ccder_decode_sequence_tl(&body_end, der, end);

    p = ccder_decode_tl(CCDER_INTEGER, m_len, p, body_end);
    if (p == NULL)
        return -1;
    *m = p;
    p = ccder_decode_tl(CCDER_INTEGER, e_len, p + *m_len, body_end);
    if (p == NULL || p + *e_len != body_end)
        return -1;
    *e = p;
    // the sign octet DER puts before a top bit
    while (*m_len > 1 && **m == 0) {
        (*m)++;
        (*m_len)--;
    }
    return 0;
}

cc_size ccrsa_import_pub_n(size_t inlen, const uint8_t *der)
{
    const uint8_t *m, *e;
    size_t m_len, e_len;

    if (der == NULL || pub_parts(inlen, der, &m, &m_len, &e, &e_len) != 0)
        return 0;
    return ccn_nof_size(m_len);
}

cc_error_t ccrsa_import_pub(ccrsa_pub_ctx_t pub, size_t inlen, const uint8_t *der)
{
    const uint8_t *m, *e;
    size_t m_len, e_len;

    if (der == NULL || pub_parts(inlen, der, &m, &m_len, &e, &e_len) != 0)
        return CCERR_PARAMETER;
    return ccrsa_make_pub(pub, e_len, e, m_len, m);
}

cc_error_t ccrsa_priv_crypt(ccrsa_full_ctx_t key, cc_unit *out, const cc_unit *in)
{
    (void)key; (void)out; (void)in;
    return CCRSA_PD_UNSUPPORTED;
}

cc_error_t ccrsa_eme_pkcs1v15_encode(struct ccrng_state *rng, size_t r_size, cc_unit *r, size_t s_size,
    const uint8_t *s)
{
    (void)rng; (void)r_size; (void)r; (void)s_size; (void)s;
    return CCRSA_PD_UNSUPPORTED;
}

cc_error_t ccrsa_eme_pkcs1v15_decode(size_t *r_size, uint8_t *r, size_t s_size, cc_unit *s)
{
    (void)r_size; (void)r; (void)s_size; (void)s;
    return CCRSA_PD_UNSUPPORTED;
}

cc_error_t ccrsa_emsa_pss_encode(const struct ccdigest_info *di, const struct ccdigest_info *mgf, size_t salt_size,
    const uint8_t *salt, size_t hash_size, const uint8_t *mhash, size_t embits, uint8_t *em)
{
    (void)di; (void)mgf; (void)salt_size; (void)salt; (void)hash_size; (void)mhash; (void)embits; (void)em;
    return CCRSA_PD_UNSUPPORTED;
}

cc_error_t ccrsa_emsa_pss_decode(const struct ccdigest_info *di, const struct ccdigest_info *mgf, size_t salt_size,
    size_t hash_size, const uint8_t *mhash, size_t embits, const uint8_t *em)
{
    (void)di; (void)mgf; (void)salt_size; (void)hash_size; (void)mhash; (void)embits; (void)em;
    return CCRSA_PD_UNSUPPORTED;
}

cc_error_t ccrsa_oaep_encode(const struct ccdigest_info *di, struct ccrng_state *rng, size_t r_size, cc_unit *r,
    size_t message_len, const uint8_t *message)
{
    (void)di; (void)rng; (void)r_size; (void)r; (void)message_len; (void)message;
    return CCRSA_PD_UNSUPPORTED;
}

cc_error_t ccrsa_oaep_decode(const struct ccdigest_info *di, size_t *r_len, uint8_t *r, size_t s_size, cc_unit *s)
{
    (void)di; (void)r_len; (void)r; (void)s_size; (void)s;
    return CCRSA_PD_UNSUPPORTED;
}

cc_error_t ccrsa_generate_fips186_key(size_t nbits, ccrsa_full_ctx_t fk, size_t e_size, const void *e,
    struct ccrng_state *rng1, struct ccrng_state *rng2)
{
    (void)nbits; (void)fk; (void)e_size; (void)e; (void)rng1; (void)rng2;
    return CCRSA_PD_UNSUPPORTED;
}

size_t ccrsa_export_priv_size(ccrsa_full_ctx_t key)
{
    (void)key;
    return 0;
}

cc_error_t ccrsa_export_priv(ccrsa_full_ctx_t key, size_t out_len, uint8_t *out)
{
    (void)key; (void)out_len; (void)out;
    return CCRSA_PD_UNSUPPORTED;
}

cc_size ccrsa_import_priv_n(size_t inlen, const uint8_t *der)
{
    (void)inlen; (void)der;
    return 0;
}

cc_error_t ccrsa_import_priv(ccrsa_full_ctx_t key, size_t inlen, const uint8_t *der)
{
    (void)key; (void)inlen; (void)der;
    return CCRSA_PD_UNSUPPORTED;
}
