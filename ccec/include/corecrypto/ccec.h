/*
 * Copyright (C) 2026, PureDarwin contributors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

// pd interim LLM-written code, experimental and not secure: unaudited, unfuzzed, no side-channel review
// ccec.h - elliptic curves over the NIST prime fields (SEC 2, FIPS 186-4 D.1.2) for Security.framework's private
// copy. Public key import and export, ECDSA verification and ECDH work, through OpenSSL's libcrypto, which
// Security already links. Signing, key generation, DER private key import, ECIES and RFC 6637 key wrapping are not
// implemented yet and return CCEC_PD_UNSUPPORTED
#ifndef _CORECRYPTO_CCEC_H_
#define _CORECRYPTO_CCEC_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <corecrypto/cc.h>
#include <corecrypto/ccn.h>
#include <corecrypto/ccrng.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccasn1.h>

#define CCEC_PD_UNSUPPORTED     CCERR_INTERNAL

// a curve: its size in units and bits, and which named curve it is
struct ccec_cp {
    cc_size n;
    size_t bitlen;
    int curve;  // ccec_pd_curve
};
typedef const struct ccec_cp *ccec_const_cp_t;

#define ccec_cp_n(_cp_)             ((_cp_)->n)
#define ccec_cp_prime_bitlen(_cp_)  ((_cp_)->bitlen)
#define ccec_cp_prime_size(_cp_)    (((_cp_)->bitlen + 7) / 8)

// a key: its curve, then x, y and a spare coordinate, n units each, and for a full key the private scalar k
struct ccec_pub_ctx {
    ccec_const_cp_t cp;
    cc_unit xyz[];
};
struct ccec_full_ctx {
    ccec_const_cp_t cp;
    cc_unit xyz[];
};
typedef struct ccec_pub_ctx *ccec_pub_ctx_t;
typedef struct ccec_full_ctx *ccec_full_ctx_t;

#define ccec_pub_ctx_size(_nbytes_)     (sizeof(struct ccec_pub_ctx) + 3 * ccn_sizeof_size(_nbytes_))
#define ccec_full_ctx_size(_nbytes_)    (sizeof(struct ccec_full_ctx) + 4 * ccn_sizeof_size(_nbytes_))
#define ccec_pub_ctx_decl(_nbytes_, _name_)   cc_ctx_decl(struct ccec_pub_ctx, ccec_pub_ctx_size(_nbytes_), _name_)
#define ccec_full_ctx_decl(_nbytes_, _name_)  cc_ctx_decl(struct ccec_full_ctx, ccec_full_ctx_size(_nbytes_), _name_)
#define ccec_pub_ctx_decl_cp(_cp_, _name_)    ccec_pub_ctx_decl(ccn_sizeof_n(ccec_cp_n(_cp_)), _name_)
#define ccec_full_ctx_decl_cp(_cp_, _name_)   ccec_full_ctx_decl(ccn_sizeof_n(ccec_cp_n(_cp_)), _name_)
#define ccec_pub_ctx_clear_cp(_cp_, _name_)   cc_clear(ccec_pub_ctx_size(ccn_sizeof_n(ccec_cp_n(_cp_))), _name_)
#define ccec_full_ctx_clear_cp(_cp_, _name_)  cc_clear(ccec_full_ctx_size(ccn_sizeof_n(ccec_cp_n(_cp_))), _name_)

#define ccec_ctx_cp(_ctx_)      ((_ctx_)->cp)
#define ccec_ctx_n(_ctx_)       ccec_cp_n(ccec_ctx_cp(_ctx_))
#define ccec_ctx_bitlen(_ctx_)  ccec_cp_prime_bitlen(ccec_ctx_cp(_ctx_))
#define ccec_ctx_size(_ctx_)    ccec_cp_prime_size(ccec_ctx_cp(_ctx_))
#define ccec_ctx_x(_ctx_)       ((_ctx_)->xyz)
#define ccec_ctx_y(_ctx_)       ((_ctx_)->xyz + ccec_ctx_n(_ctx_))
#define ccec_ctx_z(_ctx_)       ((_ctx_)->xyz + 2 * ccec_ctx_n(_ctx_))
#define ccec_ctx_k(_ctx_)       ((_ctx_)->xyz + 3 * ccec_ctx_n(_ctx_))
#define ccec_ctx_pub(_full_)    ((ccec_pub_ctx_t)(_full_))
#define ccec_ctx_init(_cp_, _ctx_)  ((void)((_ctx_)->cp = (_cp_)))

// the curves' object identifiers (SEC 2 A.2), DER-encoded as ccoid_t has them
#define CC_EC_OID_SECP192R1 ((ccoid_t)"\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x01")
#define CC_EC_OID_SECP224R1 ((ccoid_t)"\x06\x05\x2B\x81\x04\x00\x21")
#define CC_EC_OID_SECP256R1 ((ccoid_t)"\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07")
#define CC_EC_OID_SECP384R1 ((ccoid_t)"\x06\x05\x2B\x81\x04\x00\x22")
#define CC_EC_OID_SECP521R1 ((ccoid_t)"\x06\x05\x2B\x81\x04\x00\x23")

#ifdef __cplusplus
extern "C" {
#endif

ccec_const_cp_t ccec_cp_192(void);
ccec_const_cp_t ccec_cp_224(void);
ccec_const_cp_t ccec_cp_256(void);
ccec_const_cp_t ccec_cp_384(void);
ccec_const_cp_t ccec_cp_521(void);

// the octets of one coordinate
size_t ccec_ccn_size(ccec_const_cp_t cp);
// a curve by its size in bits (192, 224, 256, 384 or 521)
bool ccec_keysize_is_supported(size_t keysize);
ccec_const_cp_t ccec_get_cp(size_t keysize);
// the first of the NULL-terminated curves that is keylen bits
ccec_const_cp_t ccec_curve_for_length_lookup(size_t keylen, ...);

// public keys as X9.63 (SEC 1 2.3.3) uncompressed points, 04 || x || y; import also takes a compressed one, and
// checks the point is on the curve
size_t ccec_export_pub_size(ccec_pub_ctx_t key);
void ccec_export_pub(ccec_pub_ctx_t key, void *out);
int ccec_import_pub(ccec_const_cp_t cp, size_t in_len, const uint8_t *in, ccec_pub_ctx_t key);
// a key size in bits from an X9.63 encoding's length (a public point, or a point followed by k), and the length of
// a key's encoding
size_t ccec_x963_import_pub_size(size_t in_len);
size_t ccec_x963_import_priv_size(size_t in_len);
size_t ccec_x963_export_size(int fullkey, ccec_full_ctx_t key);

// ECDSA (SEC 1 4.1) with a DER signature, SEQUENCE { r INTEGER, s INTEGER }: the largest one, and verification,
// which returns 0 with *valid set when the key and the signature could be read
size_t ccec_sign_max_size(ccec_const_cp_t cp);
int ccec_verify(ccec_pub_ctx_t key, size_t digest_len, const uint8_t *digest, size_t sig_len, const uint8_t *sig,
    bool *valid);
// ECDH (SEC 1 3.3.1): the x coordinate of k times the public point, *computed_shared_secret_len octets in and the
// coordinate size out
int ccecdh_compute_shared_secret(ccec_full_ctx_t private_key, ccec_pub_ctx_t public_key,
    size_t *computed_shared_secret_len, uint8_t *computed_shared_secret, struct ccrng_state *masking_rng);

// not implemented yet
int ccec_sign(ccec_full_ctx_t key, size_t digest_len, const uint8_t *digest, size_t *sig_len, uint8_t *sig,
    struct ccrng_state *rng);
int ccec_generate_key_fips(ccec_const_cp_t cp, struct ccrng_state *rng, ccec_full_ctx_t key);
int ccec_der_import_priv(ccec_const_cp_t cp, size_t length, const uint8_t *data, ccec_full_ctx_t full_key);
int ccec_der_import_priv_keytype(size_t length, const uint8_t *data, ccoid_t *oid, size_t *n);

// RFC 6637 (OpenPGP ECDH) key wrapping, not implemented yet
struct ccec_rfc6637_curve {
    const uint8_t *curve_oid;
    uint8_t public_key_alg;
};
struct ccec_rfc6637_wrap {
    const struct ccdigest_info *(*difun)(void);
    uint8_t kdfhash_id;
    uint8_t kek_id;
};
struct ccec_rfc6637_unwrap {
    const struct ccdigest_info *(*difun)(void);
    uint8_t kdfhash_id;
    uint8_t kek_id;
};
extern const struct ccec_rfc6637_curve ccec_rfc6637_dh_curve_p256;
extern const struct ccec_rfc6637_curve ccec_rfc6637_dh_curve_p521;
extern const struct ccec_rfc6637_wrap ccec_rfc6637_wrap_sha256_kek_aes128;
extern const struct ccec_rfc6637_wrap ccec_rfc6637_wrap_sha512_kek_aes256;
extern const struct ccec_rfc6637_unwrap ccec_rfc6637_unwrap_sha256_kek_aes128;
extern const struct ccec_rfc6637_unwrap ccec_rfc6637_unwrap_sha512_kek_aes256;

size_t ccec_rfc6637_wrap_key_size(ccec_pub_ctx_t public_key, unsigned long flags, size_t key_len);
int ccec_rfc6637_wrap_key(ccec_pub_ctx_t public_key, void *wrapped_key, unsigned long flags, uint8_t symm_alg_id,
    size_t key_len, const void *key, const struct ccec_rfc6637_curve *curve, const struct ccec_rfc6637_wrap *wrap,
    const uint8_t *fingerprint, struct ccrng_state *rng);
int ccec_rfc6637_unwrap_key(ccec_full_ctx_t private_key, size_t *key_len, void *key, unsigned long flags,
    uint8_t *symm_key_alg, const struct ccec_rfc6637_curve *curve, const struct ccec_rfc6637_unwrap *unwrap,
    const uint8_t *fingerprint, size_t wrapped_key_len, const void *wrapped_key);

#ifdef __cplusplus
}
#endif

#endif
