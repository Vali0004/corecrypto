/*
 * Copyright (C) 2026, PureDarwin contributors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

// pd interim LLM-written code, experimental and not secure: unaudited, unfuzzed, no side-channel review
#include <corecrypto/cczp_priv.h>

#if CC_UNIT_SIZE == 8 && !CC_UNIT_ALLOW_UINT128_DUNIT
    #error ccn montgomery needs a double unit
#endif

// (hi, lo) = a * b + c + d, cannot overflow a double unit
static inline cc_unit mac(cc_unit a, cc_unit b, cc_unit c, cc_unit d, cc_unit *lo)
{
    cc_dunit t = (cc_dunit)a * b + c + d;
    *lo = (cc_unit)t;
    return (cc_unit)(t >> CC_UNIT_BITS);
}

cc_unit ccn_mont_m0inv(cc_unit m0)
{
    // newton iteration, each step doubles the correct low bits starting from 3
    cc_unit x = m0;
    for (int i = 0; i < 5; i++) {
        x *= 2 - m0 * x;
    }

    return (cc_unit)0 - x;
}

void ccn_mont_r2(cc_size n, cc_unit *r2, const cc_unit *m)
{
    ccn_zero(n, r2);
    r2[0] = 1;

    // double 1 up to R^2 reducing every step, r2 < m holds throughout
    for (size_t i = 0; i < 2 * ccn_bitsof_n(n); i++) {
        cc_unit carry = ccn_add(n, r2, r2, r2);
        if (carry || ccn_cmp(n, r2, m) >= 0)
            ccn_sub(n, r2, r2, m);
    }
}

// coarsely integrated operand scanning, koc, acar and kaliski 1996
void ccn_mont_mul(cc_size n, cc_unit *r, const cc_unit *a, const cc_unit *b,
                  const cc_unit *m, cc_unit m0inv, cc_unit *t)
{
    ccn_zero(n + 2, t);

    for (cc_size i = 0; i < n; i++) {
        cc_unit c = 0;
        for (cc_size j = 0; j < n; j++) {
            c = mac(a[j], b[i], t[j], c, &t[j]);
        }
        cc_unit s = t[n] + c;
        t[n + 1] = s < c;
        t[n] = s;

        cc_unit q = t[0] * m0inv;
        cc_unit lo;
        c = mac(q, m[0], t[0], 0, &lo);
        for (cc_size j = 1; j < n; j++) {
            c = mac(q, m[j], t[j], c, &t[j - 1]);
        }
        s = t[n] + c;
        t[n - 1] = s;
        t[n] = t[n + 1] + (s < c);
    }

    // t < 2m here
    if (t[n] || ccn_cmp(n, t, m) >= 0)
        ccn_sub(n, t, t, m);
    ccn_set(n, r, t);
}

void ccn_mont_powmod(cc_size n, cc_unit *r, const cc_unit *x, cc_size en, const cc_unit *e,
                     const cc_unit *m, cc_unit m0inv, const cc_unit *r2, cc_unit *ws)
{
    cc_unit *acc = ws;
    cc_unit *xm = ws + n;
    cc_unit *t = ws + 2 * n;

    // acc = R mod m, xm = x R mod m
    ccn_zero(n, acc);
    acc[0] = 1;
    ccn_mont_mul(n, acc, acc, r2, m, m0inv, t);
    ccn_mont_mul(n, xm, x, r2, m, m0inv, t);

    // left to right square and multiply
    for (size_t i = ccn_bitlen(en, e); i-- > 0;) {
        ccn_mont_mul(n, acc, acc, acc, m, m0inv, t);
        if (ccn_bit(e, i))
            ccn_mont_mul(n, acc, acc, xm, m, m0inv, t);
    }

    // leave the montgomery domain
    ccn_zero(n, xm);
    xm[0] = 1;
    ccn_mont_mul(n, r, acc, xm, m, m0inv, t);
}
