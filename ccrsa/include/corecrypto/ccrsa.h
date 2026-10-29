/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */


#ifndef __CORECRYPTO_CCRSA_H__
#define __CORECRYPTO_CCRSA_H__

#include <corecrypto/cczp.h>

// pd: the public key layout follows xnu's EXTERNAL_HEADERS ccrsa.h, the kernel sizes and fills
// ccrsa_ctx_n through these macros before calling ccrsa_make_pub through register_crypto
//
// ccrsa_pub_ctx:
//  [cczp header]          n, bitlen, funcs
//  cc_unit m[n]           modulus
//  cc_unit m0inv          -m^-1 mod 2^CC_UNIT_BITS
//  cc_unit mr2[n]         R^2 mod m
//  cc_unit e[n]           public exponent
//
// the private and full layouts are not implemented yet

struct ccrsa_pub_ctx {
    cc_size n;
    cc_unit bitlen;
    cczp_funcs_t funcs;
    cc_unit u[];
};

typedef struct ccrsa_pub_ctx *ccrsa_pub_ctx_t;

struct ccrsa_priv_ctx {
    cc_size n;
    cc_unit bitlen;
    cczp_funcs_t funcs;
    cc_unit u[];
};

typedef struct ccrsa_priv_ctx *ccrsa_priv_ctx_t;

struct ccrsa_full_ctx {
    cc_size n;
    cc_unit bitlen;
    cczp_funcs_t funcs;
    cc_unit u[];
};

typedef struct ccrsa_full_ctx *ccrsa_full_ctx_t;

#define ccrsa_pub_ctx_size(_nbytes_)   (sizeof(struct cczp) + CC_UNIT_SIZE + 3 * ccn_sizeof_size(_nbytes_))
#define ccrsa_pub_ctx_decl(_nbytes_, _name_)    cc_ctx_decl(struct ccrsa_pub_ctx, ccrsa_pub_ctx_size(_nbytes_), _name_)
#define ccrsa_pub_ctx_clear(_nbytes_, _name_)   cc_clear(ccrsa_pub_ctx_size(_nbytes_), _name_)

#define ccrsa_ctx_zm(_ctx_)        ((cczp_t)(_ctx_))
#define ccrsa_ctx_n(_ctx_)         (ccrsa_ctx_zm(_ctx_)->n)
#define ccrsa_ctx_m(_ctx_)         ((_ctx_)->u)
#define ccrsa_ctx_m0inv(_ctx_)     ((_ctx_)->u + ccrsa_ctx_n(_ctx_))
#define ccrsa_ctx_mr2(_ctx_)       ((_ctx_)->u + ccrsa_ctx_n(_ctx_) + 1)
#define ccrsa_ctx_e(_ctx_)         ((_ctx_)->u + 2 * ccrsa_ctx_n(_ctx_) + 1)

// pd: largest modulus the verifier takes, its scratch lives on the stack
#define CCRSA_PD_MAX_MODULUS_BITS  4096

//
// Takes the exponent and modulus to form a public key.
//
// byte order is big endian. on entry ccrsa_ctx_n(pub) is the capacity in units, on return
// it is the unit count of the modulus.
//
CC_EXPORT
cc_error_t ccrsa_make_pub(ccrsa_pub_ctx_t pub,
                          size_t exp_size, const uint8_t *exp,
                          size_t mod_size, const uint8_t *mod);

// sig validation. defs need this.
// pd: returns 0 with *valid set for a well-formed call, a NULL oid means a bare digest (rfc 4346)
CC_EXPORT
cc_error_t ccrsa_verify_pkcs1v15(ccrsa_pub_ctx_t pub,
                                 const uint8_t *oid,
                                 size_t digest_size,
                                 const uint8_t *digest,
                                 size_t sig_size,
                                 const uint8_t *sig,
                                 bool *valid);

#endif /* __CORECRYPTO_CCRSA_H__ */
