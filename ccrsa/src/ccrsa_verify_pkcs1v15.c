/*
 * Copyright (C) 2026, PureDarwin contributors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

// pd interim LLM-written code, experimental and not secure: unaudited, unfuzzed, no side-channel review
#include <corecrypto/ccrsa.h>
#include <corecrypto/cczp_priv.h>
#include <corecrypto/ccasn1.h>

#define PD_MAX_N        ccn_nof(CCRSA_PD_MAX_MODULUS_BITS)
#define PD_MAX_K        (CCRSA_PD_MAX_MODULUS_BITS / 8)

// emsa-pkcs1-v1_5 encoding, rfc 8017 9.2, the digestinfo der is built from the oid
static int emsa_pkcs1v15_encode(size_t k, uint8_t *em, const uint8_t *oid, size_t dlen, const uint8_t *digest)
{
    size_t tlen = dlen;
    size_t olen = 0;

    if (oid) {
        olen = ccoid_size(oid);
        // digestinfo ::= sequence { sequence { oid, null }, octet string }, short-form lengths only
        tlen = 2 + (2 + olen + 2) + (2 + dlen);
        if (tlen - 2 > 127)
            return CCERR_PARAMETER;
    }

    // step 3, k >= tLen + 11
    if (k < tlen + 11)
        return CCERR_PARAMETER;

    // step 5, EM = 0x00 || 0x01 || PS || 0x00 || T with PS all 0xff
    size_t pslen = k - tlen - 3;
    uint8_t *p = em;
    *p++ = 0x00;
    *p++ = 0x01;
    for (size_t i = 0; i < pslen; i++) {
        *p++ = 0xff;
    }
    *p++ = 0x00;

    if (oid) {
        *p++ = 0x30;
        *p++ = (uint8_t)(tlen - 2);
        *p++ = 0x30;
        *p++ = (uint8_t)(olen + 2);
        cc_copy(olen, p, oid);
        p += olen;
        *p++ = 0x05;
        *p++ = 0x00;
        *p++ = 0x04;
        *p++ = (uint8_t)dlen;
    }
    cc_copy(dlen, p, digest);

    return CCERR_OK;
}

// rsassa-pkcs1-v1_5-verify, rfc 8017 8.2.2
cc_error_t ccrsa_verify_pkcs1v15(ccrsa_pub_ctx_t pub,
                                 const uint8_t *oid,
                                 size_t digest_size,
                                 const uint8_t *digest,
                                 size_t sig_size,
                                 const uint8_t *sig,
                                 bool *valid)
{
    cc_size n = ccrsa_ctx_n(pub);
    size_t k = (pub->bitlen + 7) / 8;
    cc_unit s[PD_MAX_N];
    cc_unit ws[3 * PD_MAX_N + 2];
    uint8_t em[PD_MAX_K];
    uint8_t em2[PD_MAX_K];
    cc_error_t rc;

    *valid = false;
    if (n > PD_MAX_N || k > PD_MAX_K)
        return CCERR_PARAMETER;

    // step 1, the signature is exactly k octets
    if (sig_size != k)
        return CCERR_OK;

    // step 2, rsavp1 (5.2.2) rejects s outside [0, n - 1]
    if (ccn_read_uint(n, s, sig_size, sig) != CCERR_OK || ccn_cmp(n, s, ccrsa_ctx_m(pub)) >= 0)
        return CCERR_OK;
    ccn_mont_powmod(n, s, s, n, ccrsa_ctx_e(pub), ccrsa_ctx_m(pub), *ccrsa_ctx_m0inv(pub), ccrsa_ctx_mr2(pub), ws);
    if (ccn_write_uint_padded(n, s, k, em) != CCERR_OK)
        return CCERR_OK;

    // step 3 and 4, compare against the encoding of the expected digest
    rc = emsa_pkcs1v15_encode(k, em2, oid, digest_size, digest);
    if (rc != CCERR_OK)
        return rc;

    *valid = cc_cmp_safe(k, em, em2) == 0;
    cc_clear(sizeof(em), em);
    cc_clear(sizeof(em2), em2);

    return CCERR_OK;
}
