/*
 * Copyright (C) 2026, PureDarwin contributors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

// pd interim LLM-written code, experimental and not secure: unaudited, unfuzzed, no side-channel review
// ccdh.h - finite-field Diffie-Hellman for Security.framework's private copy. The group (prime, generator, and the
// private key length) and the key contexts are laid out for real, the key operations are not implemented yet and
// return CCDH_PD_UNSUPPORTED
#ifndef _CORECRYPTO_CCDH_H_
#define _CORECRYPTO_CCDH_H_

#include <corecrypto/cc.h>
#include <corecrypto/ccn.h>
#include <corecrypto/cczp.h>
#include <corecrypto/ccrng.h>

#ifndef CC_MAX_ALIGNMENT
#define CC_MAX_ALIGNMENT    16
#endif
#define CCDH_PD_UNSUPPORTED CCERR_INTERNAL

// a group is a cczp over the prime, followed by the reciprocal, the generator and the private key length:
//  u[0, n)             prime, then u[n] -p^-1 mod 2^CC_UNIT_BITS and u[n + 1, 2n + 1) R^2 mod p, as cczp_init sets
//  u[2n + 1, 3n + 2)   reciprocal (n + 1 units)
//  u[3n + 2, 4n + 2)   generator
//  u[4n + 2]           private key length in bits, 0 for the group's default
typedef struct cczp *ccdh_gp_t;
typedef const struct cczp *ccdh_const_gp_t;

#define ccdh_gp_size(_nbytes_)  (sizeof(struct cczp) + 4 * ccn_sizeof_size(_nbytes_) + 3 * CC_UNIT_SIZE)
#define ccdh_gp_n(_gp_)         ((_gp_)->n)
#define CCDH_GP_N(_gp_)         ((_gp_)->n)
#define CCDH_GP_ZP(_gp_)        ((cczp_t)(_gp_))
#define CCDH_GP_PRIME(_gp_)     ((_gp_)->u)
#define CCDH_GP_RECIP(_gp_)     ((_gp_)->u + 2 * (_gp_)->n + 1)
#define CCDH_GP_G(_gp_)         ((_gp_)->u + 3 * (_gp_)->n + 2)
#define CCDH_GP_L(_gp_)         ((_gp_)->u[4 * (_gp_)->n + 2])

// a key is its group and y, a full one also x
struct ccdh_pub_ctx {
    ccdh_const_gp_t gp;
    cc_unit xy[];
};
struct ccdh_full_ctx {
    ccdh_const_gp_t gp;
    cc_unit xy[];
};
typedef struct ccdh_pub_ctx *ccdh_pub_ctx_t;
typedef struct ccdh_full_ctx *ccdh_full_ctx_t;

#define ccdh_pub_ctx_size(_nbytes_)     (sizeof(struct ccdh_pub_ctx) + ccn_sizeof_size(_nbytes_))
#define ccdh_full_ctx_size(_nbytes_)    (sizeof(struct ccdh_full_ctx) + 2 * ccn_sizeof_size(_nbytes_))
#define ccdh_pub_ctx_decl_gp(_gp_, _name_) \
    cc_ctx_decl(struct ccdh_pub_ctx, ccdh_pub_ctx_size(ccn_sizeof_n(ccdh_gp_n(_gp_))), _name_)
#define ccdh_ctx_gp(_ctx_)      ((_ctx_)->gp)
#define ccdh_ctx_y(_ctx_)       ((_ctx_)->xy)
#define ccdh_ctx_x(_ctx_)       ((_ctx_)->xy + ccdh_gp_n((_ctx_)->gp))

#ifdef __cplusplus
extern "C" {
#endif

// not implemented yet
int ccdh_generate_key(ccdh_const_gp_t gp, struct ccrng_state *rng, ccdh_full_ctx_t key);
int ccdh_import_pub(ccdh_const_gp_t gp, size_t in_len, const uint8_t *in, ccdh_pub_ctx_t key);
int ccdh_compute_key(ccdh_full_ctx_t private_key, ccdh_pub_ctx_t public_key, cc_unit *r);

#ifdef __cplusplus
}
#endif

#endif
