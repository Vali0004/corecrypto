/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CCZP_H__
#define __CORECRYPTO_CCZP_H__

#include <corecrypto/ccn.h>

CC_BEGIN_DECLS

typedef struct cczp *cczp_t;
typedef const struct cczp *cczp_const_t;

/* This is actually not a public thing. "Reality can be whatever I want." */
typedef const struct cczp_funcs *cczp_funcs_t;

// ERRATA: cczp is inconsistent across Apple corecrypto. Do we /actually/ care about that though?
struct cczp {
    cc_size n;
    cc_unit bitlen;
    cczp_funcs_t funcs;
    cc_unit u[];
};

// pd: n and the modulus at u are set, the rest of the context (its bit length, -m^-1 mod 2^CC_UNIT_BITS at u[n],
// R^2 mod m at u[n + 1]) is computed from them. The reciprocal is not used, Montgomery multiplication needs none
int cczp_init(cczp_t zp);
int cczp_init_with_recip(cczp_t zp, const cc_unit *recip);

CC_END_DECLS

#endif /* __CORECRYPTO_CCZP_H__  */
