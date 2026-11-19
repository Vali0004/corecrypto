/*
 * Copyright (C) 2026, PureDarwin contributors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

// pd interim LLM-written code, experimental and not secure: unaudited, unfuzzed, no side-channel review
// ccn_extra.c - the ccn helpers Security.framework uses on top of the fork's arithmetic
#include <string.h>
#include <corecrypto/ccn.h>

cc_unit ccn_add1(cc_size n, cc_unit *r, const cc_unit *s, cc_unit v)
{
    for (cc_size i = 0; i < n; i++) {
        cc_unit x = s[i] + v;
        v = x < v;
        r[i] = x;
    }
    return v;
}

int ccn_cmpn(cc_size ns, const cc_unit *s, cc_size nt, const cc_unit *t)
{
    cc_size n = ns > nt ? ns : nt;

    for (cc_size i = n; i > 0; i--) {
        cc_unit a = i - 1 < ns ? s[i - 1] : 0, b = i - 1 < nt ? t[i - 1] : 0;
        if (a != b)
            return a > b ? 1 : -1;
    }
    return 0;
}

void ccn_seti(cc_size n, cc_unit *r, cc_unit v)
{
    if (n == 0)
        return;
    memset(r, 0, n * sizeof(cc_unit));
    r[0] = v;
}

size_t ccn_write_uint_size(cc_size n, const cc_unit *s)
{
    return (ccn_bitlen(n, s) + 7) / 8;
}

static uint8_t octet(cc_size n, const cc_unit *s, size_t k)
{
    size_t u = k / CC_UNIT_SIZE;

    return u < n ? (uint8_t)(s[u] >> (8 * (k % CC_UNIT_SIZE))) : 0;
}

void ccn_write_uint(cc_size n, const cc_unit *s, size_t out_nbytes, void *out)
{
    size_t size = ccn_write_uint_size(n, s), len = out_nbytes < size ? out_nbytes : size;
    uint8_t *o = out;

    for (size_t i = 0; i < len; i++)
        o[i] = octet(n, s, len - 1 - i);
}

size_t ccn_write_int_size(cc_size n, const cc_unit *s)
{
    size_t bits = ccn_bitlen(n, s);

    // a number whose bit length is a multiple of 8 needs the extra sign octet, and zero is one octet
    return bits / 8 + 1;
}

void ccn_write_int(cc_size n, const cc_unit *s, size_t out_nbytes, void *out)
{
    size_t size = ccn_write_int_size(n, s);
    uint8_t *o = out;

    if (out_nbytes < size) {
        // only the low octets fit
        for (size_t i = 0; i < out_nbytes; i++)
            o[i] = octet(n, s, out_nbytes - 1 - i);
        return;
    }
    memset(o, 0, out_nbytes - size);
    for (size_t i = 0; i < size; i++)
        o[out_nbytes - size + i] = octet(n, s, size - 1 - i);
}
