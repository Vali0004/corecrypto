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


// pd: what Security.framework's private copy uses. A full (private) key is the public key followed by room for
// the private part, so ccrsa_ctx_public and the ccrsa_ctx_ macros work on either. The private operations are not
// implemented yet: they return CCRSA_PD_UNSUPPORTED, and key generation and private-key import fail
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccrng.h>

#define CCRSA_PD_UNSUPPORTED       CCERR_INTERNAL
#define ccrsa_full_ctx_size(_nbytes_)   (ccrsa_pub_ctx_size(_nbytes_) + 5 * ccn_sizeof_size(_nbytes_))
#define ccrsa_full_ctx_decl(_nbytes_, _name_)   cc_ctx_decl(struct ccrsa_full_ctx, ccrsa_full_ctx_size(_nbytes_), _name_)
#define ccrsa_ctx_public(_fk_)     ((ccrsa_pub_ctx_t)(_fk_))

// the modulus's size in octets
size_t ccrsa_block_size(ccrsa_pub_ctx_t pub);
// out = in^e mod m, n units each
cc_error_t ccrsa_pub_crypt(ccrsa_pub_ctx_t pub, cc_unit *out, const cc_unit *in);
// a PKCS#1 RSAPublicKey (RFC 8017 A.1.1): the units its modulus needs, 0 when it is not one, and the key into pub,
// whose ccrsa_ctx_n is its capacity
cc_size ccrsa_import_pub_n(size_t inlen, const uint8_t *der);
cc_error_t ccrsa_import_pub(ccrsa_pub_ctx_t pub, size_t inlen, const uint8_t *der);
// EMSA-PKCS1-v1_5 (RFC 8017 9.2) into em, and em checked against the encoding of dgst: 0 when it matches. A NULL
// oid is a bare digest
cc_error_t ccrsa_emsa_pkcs1v15_encode(size_t emlen, uint8_t *em, size_t dgstlen, const uint8_t *dgst,
    const uint8_t *oid);
cc_error_t ccrsa_emsa_pkcs1v15_verify(size_t emlen, uint8_t *em, size_t dgstlen, const uint8_t *dgst,
    const uint8_t *oid);

// not implemented yet
cc_error_t ccrsa_priv_crypt(ccrsa_full_ctx_t key, cc_unit *out, const cc_unit *in);
cc_error_t ccrsa_eme_pkcs1v15_encode(struct ccrng_state *rng, size_t r_size, cc_unit *r, size_t s_size,
    const uint8_t *s);
cc_error_t ccrsa_eme_pkcs1v15_decode(size_t *r_size, uint8_t *r, size_t s_size, cc_unit *s);
cc_error_t ccrsa_emsa_pss_encode(const struct ccdigest_info *di, const struct ccdigest_info *mgf, size_t salt_size,
    const uint8_t *salt, size_t hash_size, const uint8_t *mhash, size_t embits, uint8_t *em);
cc_error_t ccrsa_emsa_pss_decode(const struct ccdigest_info *di, const struct ccdigest_info *mgf, size_t salt_size,
    size_t hash_size, const uint8_t *mhash, size_t embits, const uint8_t *em);
cc_error_t ccrsa_oaep_encode(const struct ccdigest_info *di, struct ccrng_state *rng, size_t r_size, cc_unit *r,
    size_t message_len, const uint8_t *message);
cc_error_t ccrsa_oaep_decode(const struct ccdigest_info *di, size_t *r_len, uint8_t *r, size_t s_size, cc_unit *s);
cc_error_t ccrsa_generate_fips186_key(size_t nbits, ccrsa_full_ctx_t fk, size_t e_size, const void *e,
    struct ccrng_state *rng1, struct ccrng_state *rng2);
size_t ccrsa_export_priv_size(ccrsa_full_ctx_t key);
cc_error_t ccrsa_export_priv(ccrsa_full_ctx_t key, size_t out_len, uint8_t *out);
cc_size ccrsa_import_priv_n(size_t inlen, const uint8_t *der);
cc_error_t ccrsa_import_priv(ccrsa_full_ctx_t key, size_t inlen, const uint8_t *der);

#endif /* __CORECRYPTO_CCRSA_H__ */
