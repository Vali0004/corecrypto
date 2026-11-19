/*
 * Copyright (C) 2026, PureDarwin contributors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

// pd interim LLM-written code, experimental and not secure: unaudited, unfuzzed, no side-channel review
// ccec_pd_security.c - the EC API Security.framework's private copy uses. The curve arithmetic is OpenSSL's
// (libcrypto, Apache-2.0, which Security links privately): this file only moves keys between corecrypto's layout
// and OpenSSL's. Only Security.framework builds it, the kext and libSystem do not
#include <stdarg.h>
#include <string.h>
#include <corecrypto/ccec.h>
#include <corecrypto/ccecies.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/ecdh.h>
#include <openssl/obj_mac.h>

enum ccec_pd_curve { PD_P192, PD_P224, PD_P256, PD_P384, PD_P521 };

static const struct ccec_cp curves[] = {
    [PD_P192] = { ccn_nof(192), 192, PD_P192 },
    [PD_P224] = { ccn_nof(224), 224, PD_P224 },
    [PD_P256] = { ccn_nof(256), 256, PD_P256 },
    [PD_P384] = { ccn_nof(384), 384, PD_P384 },
    [PD_P521] = { ccn_nof(521), 521, PD_P521 },
};
static const int nids[] = {
    [PD_P192] = NID_X9_62_prime192v1,
    [PD_P224] = NID_secp224r1,
    [PD_P256] = NID_X9_62_prime256v1,
    [PD_P384] = NID_secp384r1,
    [PD_P521] = NID_secp521r1,
};

ccec_const_cp_t ccec_cp_192(void) { return &curves[PD_P192]; }
ccec_const_cp_t ccec_cp_224(void) { return &curves[PD_P224]; }
ccec_const_cp_t ccec_cp_256(void) { return &curves[PD_P256]; }
ccec_const_cp_t ccec_cp_384(void) { return &curves[PD_P384]; }
ccec_const_cp_t ccec_cp_521(void) { return &curves[PD_P521]; }

size_t ccec_ccn_size(ccec_const_cp_t cp)
{
    return ccec_cp_prime_size(cp);
}

ccec_const_cp_t ccec_get_cp(size_t keysize)
{
    for (size_t i = 0; i < sizeof(curves) / sizeof(curves[0]); i++)
        if (curves[i].bitlen == keysize)
            return &curves[i];
    return NULL;
}

bool ccec_keysize_is_supported(size_t keysize)
{
    return ccec_get_cp(keysize) != NULL;
}

ccec_const_cp_t ccec_curve_for_length_lookup(size_t keylen, ...)
{
    ccec_const_cp_t cp, found = NULL;
    va_list ap;

    va_start(ap, keylen);
    while (found == NULL && (cp = va_arg(ap, ccec_const_cp_t)) != NULL)
        if (ccec_cp_prime_bitlen(cp) == keylen)
            found = cp;
    va_end(ap);
    return found;
}

// the curve size in bits whose coordinates are bytes octets
static size_t bits_for_octets(size_t bytes)
{
    for (size_t i = 0; i < sizeof(curves) / sizeof(curves[0]); i++)
        if (ccec_cp_prime_size(&curves[i]) == bytes)
            return curves[i].bitlen;
    return 0;
}

size_t ccec_x963_import_pub_size(size_t in_len)
{
    return in_len < 3 || (in_len - 1) % 2 != 0 ? 0 : bits_for_octets((in_len - 1) / 2);
}

size_t ccec_x963_import_priv_size(size_t in_len)
{
    return in_len < 4 || (in_len - 1) % 3 != 0 ? 0 : bits_for_octets((in_len - 1) / 3);
}

size_t ccec_x963_export_size(int fullkey, ccec_full_ctx_t key)
{
    return 1 + (fullkey ? 3 : 2) * ccec_ctx_size(key);
}

size_t ccec_export_pub_size(ccec_pub_ctx_t key)
{
    return 1 + 2 * ccec_ctx_size(key);
}

void ccec_export_pub(ccec_pub_ctx_t key, void *out)
{
    size_t size = ccec_ctx_size(key);
    uint8_t *o = out;

    o[0] = 0x04;
    ccn_write_uint_padded(ccec_ctx_n(key), ccec_ctx_x(key), size, o + 1);
    ccn_write_uint_padded(ccec_ctx_n(key), ccec_ctx_y(key), size, o + 1 + size);
}

// a corecrypto number into a BIGNUM, and back, size octets big-endian in between
static BIGNUM *bn_from_ccn(cc_size n, const cc_unit *s, size_t size)
{
    uint8_t buf[80];

    if (size > sizeof(buf) || ccn_write_uint_padded(n, s, size, buf) != CCERR_OK)
        return NULL;
    BIGNUM *bn = BN_bin2bn(buf, (int)size, NULL);
    cc_clear(sizeof(buf), buf);
    return bn;
}

static int ccn_from_bn(cc_size n, cc_unit *r, const BIGNUM *bn, size_t size)
{
    uint8_t buf[80];
    int rc;

    if (size > sizeof(buf) || BN_bn2binpad(bn, buf, (int)size) != (int)size)
        return CCERR_PARAMETER;
    rc = ccn_read_uint(n, r, size, buf);
    cc_clear(sizeof(buf), buf);
    return rc;
}

// the key as an OpenSSL key on its curve: the public point always, the private scalar too when k is given
static EC_KEY *ec_key(ccec_pub_ctx_t pub, const cc_unit *k)
{
    ccec_const_cp_t cp = ccec_ctx_cp(pub);
    size_t size = ccec_cp_prime_size(cp);
    EC_KEY *key = EC_KEY_new_by_curve_name(nids[cp->curve]);
    BIGNUM *x = bn_from_ccn(ccec_ctx_n(pub), ccec_ctx_x(pub), size);
    BIGNUM *y = bn_from_ccn(ccec_ctx_n(pub), ccec_ctx_y(pub), size);
    BIGNUM *d = k != NULL ? bn_from_ccn(ccec_ctx_n(pub), k, size) : NULL;
    int ok = key != NULL && x != NULL && y != NULL && (k == NULL || d != NULL)
        && EC_KEY_set_public_key_affine_coordinates(key, x, y) == 1
        && (d == NULL || EC_KEY_set_private_key(key, d) == 1);

    BN_free(x);
    BN_free(y);
    BN_clear_free(d);
    if (!ok) {
        EC_KEY_free(key);
        return NULL;
    }
    return key;
}

int ccec_import_pub(ccec_const_cp_t cp, size_t in_len, const uint8_t *in, ccec_pub_ctx_t key)
{
    EC_GROUP *group = EC_GROUP_new_by_curve_name(nids[cp->curve]);
    EC_POINT *point = group != NULL ? EC_POINT_new(group) : NULL;
    BIGNUM *x = BN_new(), *y = BN_new();
    int rc = CCERR_PARAMETER;

    // oct2point takes the uncompressed and the compressed forms, and refuses a point that is not on the curve
    if (point != NULL && x != NULL && y != NULL && EC_POINT_oct2point(group, point, in, in_len, NULL) == 1
        && EC_POINT_get_affine_coordinates(group, point, x, y, NULL) == 1) {
        ccec_ctx_init(cp, key);
        rc = ccn_from_bn(ccec_cp_n(cp), ccec_ctx_x(key), x, ccec_cp_prime_size(cp));
        if (rc == CCERR_OK)
            rc = ccn_from_bn(ccec_cp_n(cp), ccec_ctx_y(key), y, ccec_cp_prime_size(cp));
        if (rc == CCERR_OK)
            ccn_seti(ccec_cp_n(cp), ccec_ctx_z(key), 1);
    }
    BN_free(x);
    BN_free(y);
    EC_POINT_free(point);
    EC_GROUP_free(group);
    return rc;
}

size_t ccec_sign_max_size(ccec_const_cp_t cp)
{
    // SEQUENCE of two INTEGERs of up to size + 1 octets (a sign octet), each with a tag and a length of up to 2
    // octets, and the SEQUENCE's own tag and up to 3 length octets
    size_t size = ccec_cp_prime_size(cp);
    return 2 * (1 + 2 + size + 1) + 1 + 3;
}

int ccec_verify(ccec_pub_ctx_t key, size_t digest_len, const uint8_t *digest, size_t sig_len, const uint8_t *sig,
    bool *valid)
{
    EC_KEY *k;
    int r;

    *valid = false;
    k = ec_key(key, NULL);
    if (k == NULL)
        return CCERR_PARAMETER;
    // 1 good, 0 bad, -1 a signature that is not DER: that is a bad one too
    r = ECDSA_verify(0, digest, (int)digest_len, sig, (int)sig_len, k);
    *valid = r == 1;
    EC_KEY_free(k);
    return CCERR_OK;
}

int ccecdh_compute_shared_secret(ccec_full_ctx_t private_key, ccec_pub_ctx_t public_key,
    size_t *computed_shared_secret_len, uint8_t *computed_shared_secret, struct ccrng_state *masking_rng)
{
    size_t size = ccec_ctx_size(private_key);
    EC_KEY *mine, *theirs;
    int n, rc = CCERR_PARAMETER;

    (void)masking_rng;
    if (*computed_shared_secret_len < size || ccec_ctx_cp(public_key) != ccec_ctx_cp(private_key))
        return CCERR_PARAMETER;
    mine = ec_key(ccec_ctx_pub(private_key), ccec_ctx_k(private_key));
    theirs = ec_key(public_key, NULL);
    if (mine != NULL && theirs != NULL) {
        n = ECDH_compute_key(computed_shared_secret, size, EC_KEY_get0_public_key(theirs), mine, NULL);
        if (n == (int)size) {
            *computed_shared_secret_len = size;
            rc = CCERR_OK;
        }
    }
    EC_KEY_free(mine);
    EC_KEY_free(theirs);
    return rc;
}

int ccec_sign(ccec_full_ctx_t key, size_t digest_len, const uint8_t *digest, size_t *sig_len, uint8_t *sig,
    struct ccrng_state *rng)
{
    (void)key; (void)digest_len; (void)digest; (void)sig_len; (void)sig; (void)rng;
    return CCEC_PD_UNSUPPORTED;
}

int ccec_generate_key_fips(ccec_const_cp_t cp, struct ccrng_state *rng, ccec_full_ctx_t key)
{
    (void)cp; (void)rng; (void)key;
    return CCEC_PD_UNSUPPORTED;
}

int ccec_der_import_priv(ccec_const_cp_t cp, size_t length, const uint8_t *data, ccec_full_ctx_t full_key)
{
    (void)cp; (void)length; (void)data; (void)full_key;
    return CCEC_PD_UNSUPPORTED;
}

int ccec_der_import_priv_keytype(size_t length, const uint8_t *data, ccoid_t *oid, size_t *n)
{
    (void)length; (void)data; (void)oid; (void)n;
    return CCEC_PD_UNSUPPORTED;
}

const struct ccec_rfc6637_curve ccec_rfc6637_dh_curve_p256 = { NULL, 18 };
const struct ccec_rfc6637_curve ccec_rfc6637_dh_curve_p521 = { NULL, 18 };
const struct ccec_rfc6637_wrap ccec_rfc6637_wrap_sha256_kek_aes128 = { NULL, 8, 7 };
const struct ccec_rfc6637_wrap ccec_rfc6637_wrap_sha512_kek_aes256 = { NULL, 10, 9 };
const struct ccec_rfc6637_unwrap ccec_rfc6637_unwrap_sha256_kek_aes128 = { NULL, 8, 7 };
const struct ccec_rfc6637_unwrap ccec_rfc6637_unwrap_sha512_kek_aes256 = { NULL, 10, 9 };

size_t ccec_rfc6637_wrap_key_size(ccec_pub_ctx_t public_key, unsigned long flags, size_t key_len)
{
    (void)public_key; (void)flags; (void)key_len;
    return 0;
}

int ccec_rfc6637_wrap_key(ccec_pub_ctx_t public_key, void *wrapped_key, unsigned long flags, uint8_t symm_alg_id,
    size_t key_len, const void *key, const struct ccec_rfc6637_curve *curve, const struct ccec_rfc6637_wrap *wrap,
    const uint8_t *fingerprint, struct ccrng_state *rng)
{
    (void)public_key; (void)wrapped_key; (void)flags; (void)symm_alg_id; (void)key_len; (void)key; (void)curve;
    (void)wrap; (void)fingerprint; (void)rng;
    return CCEC_PD_UNSUPPORTED;
}

int ccec_rfc6637_unwrap_key(ccec_full_ctx_t private_key, size_t *key_len, void *key, unsigned long flags,
    uint8_t *symm_key_alg, const struct ccec_rfc6637_curve *curve, const struct ccec_rfc6637_unwrap *unwrap,
    const uint8_t *fingerprint, size_t wrapped_key_len, const void *wrapped_key)
{
    (void)private_key; (void)key_len; (void)key; (void)flags; (void)symm_key_alg; (void)curve; (void)unwrap;
    (void)fingerprint; (void)wrapped_key_len; (void)wrapped_key;
    return CCEC_PD_UNSUPPORTED;
}

void ccecies_encrypt_gcm_setup(ccecies_gcm_t ecies, const struct ccdigest_info *di, struct ccrng_state *rng,
    const struct ccmode_gcm *aes_gcm_enc, uint32_t cipher_key_size, uint32_t mac_tag_size, uint32_t options)
{
    ecies->di = di;
    ecies->rng = rng;
    ecies->gcm = aes_gcm_enc;
    ecies->key_length = cipher_key_size;
    ecies->mac_length = mac_tag_size;
    ecies->options = options;
}

void ccecies_decrypt_gcm_setup(ccecies_gcm_t ecies, const struct ccdigest_info *di,
    const struct ccmode_gcm *aes_gcm_dec, uint32_t cipher_key_size, uint32_t mac_tag_size, uint32_t options)
{
    ccecies_encrypt_gcm_setup(ecies, di, NULL, aes_gcm_dec, cipher_key_size, mac_tag_size, options);
}

size_t ccecies_encrypt_gcm_ciphertext_size(ccec_pub_ctx_t public_key, ccecies_gcm_t ecies, size_t plaintext_len)
{
    (void)public_key; (void)ecies; (void)plaintext_len;
    return 0;
}

size_t ccecies_decrypt_gcm_plaintext_size(ccec_full_ctx_t full_key, ccecies_gcm_t ecies, size_t ciphertext_len)
{
    (void)full_key; (void)ecies; (void)ciphertext_len;
    return 0;
}

int ccecies_encrypt_gcm(ccec_pub_ctx_t public_key, const ccecies_gcm_t ecies, size_t plaintext_len,
    const uint8_t *plaintext, size_t sharedinfo1_byte_len, const void *sharedinfo_1, size_t sharedinfo2_byte_len,
    const void *sharedinfo_2, size_t *encrypted_blob_len, uint8_t *encrypted_blob)
{
    (void)public_key; (void)ecies; (void)plaintext_len; (void)plaintext; (void)sharedinfo1_byte_len;
    (void)sharedinfo_1; (void)sharedinfo2_byte_len; (void)sharedinfo_2; (void)encrypted_blob_len;
    (void)encrypted_blob;
    return CCEC_PD_UNSUPPORTED;
}

int ccecies_decrypt_gcm(ccec_full_ctx_t full_key, const ccecies_gcm_t ecies, size_t encrypted_blob_len,
    const uint8_t *encrypted_blob, size_t sharedinfo1_byte_len, const void *sharedinfo_1,
    size_t sharedinfo2_byte_len, const void *sharedinfo_2, size_t *plaintext_len, uint8_t *plaintext)
{
    (void)full_key; (void)ecies; (void)encrypted_blob_len; (void)encrypted_blob; (void)sharedinfo1_byte_len;
    (void)sharedinfo_1; (void)sharedinfo2_byte_len; (void)sharedinfo_2; (void)plaintext_len; (void)plaintext;
    return CCEC_PD_UNSUPPORTED;
}
