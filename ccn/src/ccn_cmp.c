/*
 * Copyright (C) 2026, PureDarwin contributors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

// pd interim LLM-written code, experimental and not secure: unaudited, unfuzzed, no side-channel review

#include <corecrypto/ccn.h>

int ccn_cmp(cc_size n, const cc_unit *s, const cc_unit *t)
{
    while (n--) {
        if (s[n] != t[n])
            return s[n] > t[n] ? 1 : -1;
    }

    return 0;
}

cc_size ccn_n(cc_size n, const cc_unit *s)
{
    while (n && s[n - 1] == 0)
        n--;

    return n;
}

size_t ccn_bitlen(cc_size n, const cc_unit *s)
{
    n = ccn_n(n, s);
    if (n == 0)
        return 0;

    size_t bits = ccn_bitsof_n(n - 1);
    for (cc_unit top = s[n - 1]; top; top >>= 1)
        bits++;

    return bits;
}

void ccn_zero(cc_size n, cc_unit *r)
{
    for (cc_size i = 0; i < n; i++) {
        r[i] = 0;
    }
}

void ccn_set(cc_size n, cc_unit *r, const cc_unit *s)
{
    for (cc_size i = 0; i < n; i++) {
        r[i] = s[i];
    }
}
