/*
 * Copyright (C) 2026, PureDarwin contributors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

// pd interim LLM-written code, experimental and not secure: unaudited, unfuzzed, no side-channel review
// cczp_init.c - a modulus's Montgomery constants, in the layout ccrsa's public key uses
#include <corecrypto/cczp.h>
#include <corecrypto/cczp_priv.h>

int cczp_init(cczp_t zp)
{
    cc_size n = zp->n;
    const cc_unit *m = zp->u;

    zp->bitlen = ccn_bitlen(n, m);
    zp->funcs = NULL;
    zp->u[n] = ccn_mont_m0inv(m[0]);
    ccn_mont_r2(n, zp->u + n + 1, m);
    return 0;
}

int cczp_init_with_recip(cczp_t zp, const cc_unit *recip)
{
    (void)recip;
    return cczp_init(zp);
}
