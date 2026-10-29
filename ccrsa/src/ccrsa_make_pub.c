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

// public key (n, e), rfc 8017 3.1
cc_error_t ccrsa_make_pub(ccrsa_pub_ctx_t pub,
                          size_t exp_size, const uint8_t *exp,
                          size_t mod_size, const uint8_t *mod)
{
    cc_size cap = ccrsa_ctx_n(pub);
    cc_unit m[ccn_nof(CCRSA_PD_MAX_MODULUS_BITS)];
    cc_size mn = ccn_nof(CCRSA_PD_MAX_MODULUS_BITS);

    if (ccn_read_uint(mn, m, mod_size, mod) != CCERR_OK)
        return CCERR_PARAMETER;

    cc_size n = ccn_n(mn, m);
    // the modulus is odd and at least 2 units, e is in [3, m)
    if (n < 2 || n > cap || (m[0] & 1) == 0)
        return CCERR_PARAMETER;

    ccrsa_ctx_n(pub) = n;
    pub->bitlen = ccn_bitlen(n, m);
    pub->funcs = NULL;
    ccn_set(n, ccrsa_ctx_m(pub), m);

    cc_unit *e = ccrsa_ctx_e(pub);
    if (ccn_read_uint(n, e, exp_size, exp) != CCERR_OK || ccn_bitlen(n, e) < 2 || ccn_cmp(n, e, m) >= 0) {
        ccrsa_ctx_n(pub) = cap;
        return CCERR_PARAMETER;
    }

    *ccrsa_ctx_m0inv(pub) = ccn_mont_m0inv(m[0]);
    ccn_mont_r2(n, ccrsa_ctx_mr2(pub), m);

    return CCERR_OK;
}
