/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

// pd: carries without a double unit, the old loop dropped the carry out of s[i] + t[i]

#include <corecrypto/ccn.h>

// r = s + t, returns the carry out of the top unit
cc_unit ccn_add(cc_size n, cc_unit *r, const cc_unit *s, const cc_unit *t)
{
    cc_unit carry = 0;

    for (cc_size i = 0; i < n; i++) {
        cc_unit a = s[i];
        cc_unit sum = a + t[i];
        cc_unit c1 = sum < a;
        cc_unit out = sum + carry;
        carry = c1 | (out < sum);
        r[i] = out;
    }

    return carry;
}
