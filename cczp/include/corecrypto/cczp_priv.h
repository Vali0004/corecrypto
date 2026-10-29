/*
 * Copyright (C) 2026, PureDarwin contributors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

// pd interim LLM-written code, experimental and not secure: unaudited, unfuzzed, no side-channel review

#ifndef __CORECRYPTO_CCZP_PRIV_H__
#define __CORECRYPTO_CCZP_PRIV_H__

#include <corecrypto/cczp.h>

CC_BEGIN_DECLS

// montgomery arithmetic mod an odd m of n units with a nonzero top unit, variable time
// R = 2^(CC_UNIT_BITS * n)

// -m[0]^-1 mod 2^CC_UNIT_BITS
CC_PRIVATE
cc_unit ccn_mont_m0inv(cc_unit m0);

// r2 = R^2 mod m
CC_PRIVATE
void ccn_mont_r2(cc_size n, cc_unit *r2, const cc_unit *m);

// r = a * b / R mod m for a, b < m, ws holds n + 2 units, r may alias a or b
CC_PRIVATE
void ccn_mont_mul(cc_size n, cc_unit *r, const cc_unit *a, const cc_unit *b,
                  const cc_unit *m, cc_unit m0inv, cc_unit *ws);

// r = x^e mod m for x < m, e of en units, ws holds 3n + 2 units
CC_PRIVATE
void ccn_mont_powmod(cc_size n, cc_unit *r, const cc_unit *x, cc_size en, const cc_unit *e,
                     const cc_unit *m, cc_unit m0inv, const cc_unit *r2, cc_unit *ws);

CC_END_DECLS

#endif /* __CORECRYPTO_CCZP_PRIV_H__ */
