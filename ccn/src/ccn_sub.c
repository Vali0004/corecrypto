/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

// pd: borrows without a double unit, the old loop lost the borrow of s[i] - t[i]

#include <corecrypto/ccn.h>

// r = s - t, returns the borrow out of the top unit
cc_unit ccn_sub(cc_size n, cc_unit *r, const cc_unit *s, const cc_unit *t)
{
    cc_unit borrow = 0;

    for (cc_size i = 0; i < n; i++) {
        cc_unit a = s[i];
        cc_unit d = a - t[i];
        cc_unit b1 = d > a;
        cc_unit out = d - borrow;
        borrow = b1 | (out > d);
        r[i] = out;
    }

    return borrow;
}
