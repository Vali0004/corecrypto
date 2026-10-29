/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
// pd interim LLM-written code, experimental and not secure: unaudited, unfuzzed, no side-channel review

#include "corecrypto_kext_if.h"
#include <libkern/libkern.h>
#include <sys/random.h>

static struct crypto_functions corecrypto_registration_if;

// pd: the aead table xnu's ipsec and skywalk call through
static const struct ccchacha20poly1305_fns ccchacha20poly1305_kernel_fns = {
    .info = ccchacha20poly1305_info,
    .init = ccchacha20poly1305_init,
    .reset = ccchacha20poly1305_reset,
    .setnonce = ccchacha20poly1305_setnonce,
    .incnonce = ccchacha20poly1305_incnonce,
    .aad = ccchacha20poly1305_aad,
    .encrypt = ccchacha20poly1305_encrypt,
    .finalize = ccchacha20poly1305_finalize,
    .decrypt = ccchacha20poly1305_decrypt,
    .verify = ccchacha20poly1305_verify,
};

kern_return_t corecrypto_start(kmod_info_t *ki, void *d);
kern_return_t corecrypto_stop(kmod_info_t *ki, void *d);

#if 1 // pd: xnu 12377 always uses the crypto_digest/hmac/random contract
//
//  [INTERNAL PROJECT TRACKING ANNOTATION]
//  Project:            corecrypto
//  Track:              Goulburn, Errinundra, Aurora, Marigold
//  Completion Status:  In Progress
//
//  Description:
//  The contract with XNU regarding SPI has changed in ways so that
//  behaviour is similar to CommonCrypto's interfaces.
//
//  We need to update based on that, and make sure that backwards compatibility
//  is not broken along the way.
//
//  Affected projects (subject to change):
//      corecrypto
//

#define CRYPTO_DIGEST_ALGS_MAX  6

static const struct ccdigest_info *crypto_digest_algs[CRYPTO_DIGEST_ALGS_MAX];

//
// For functions with a ctx_size, should we client_crash when they don't sync?
//
static size_t crypto_digest_ctx_size(crypto_digest_alg_t alg) {
    return ccdigest_di_size(crypto_digest_algs[alg]);
}

static void crypto_digest_init(crypto_digest_alg_t alg,
                        void *ctx,
                        size_t ctx_size) {
    cc_client_crash((ccdigest_di_size(crypto_digest_algs[alg])) != ctx_size, "ctx_size != ccdigest_di_size");
    ccdigest_init(crypto_digest_algs[alg], (ccdigest_ctx_t)ctx);
}

static void crypto_digest_update(crypto_digest_alg_t alg,
                          void *ctx,
                          size_t ctx_size,
                          const void *data,
                          size_t data_size)
{
    cc_client_crash((ccdigest_di_size(crypto_digest_algs[alg])) != ctx_size, "ctx_size != ccdigest_di_size");
    ccdigest_update(crypto_digest_algs[alg], (ccdigest_ctx_t)ctx, data_size, data);
}

#define DIGEST_MAX_OUTPUT_SIZE  64

static void crypto_digest_final(crypto_digest_alg_t alg,
                         void *ctx,
                         size_t ctx_size,
                         void *digest,
                         size_t digest_size) {
    uint8_t buf[DIGEST_MAX_OUTPUT_SIZE];
    
    cc_client_crash((ccdigest_di_size(crypto_digest_algs[alg])) != ctx_size, "ctx_size != ccdigest_di_size");
    cc_client_crash(digest_size > crypto_digest_algs[alg]->output_size, "digest_size > output_size");
    ccdigest_final(crypto_digest_algs[alg], (ccdigest_ctx_t)ctx, buf);
    cc_copy(digest_size, digest, buf);
}

static void crypto_digest(crypto_digest_alg_t alg,
                   const void *data,
                   size_t data_size,
                   void *digest,
                   size_t digest_size) {
    uint8_t buf[DIGEST_MAX_OUTPUT_SIZE];

    cc_client_crash(digest_size > crypto_digest_algs[alg]->output_size, "digest_size > output_size");
    ccdigest(crypto_digest_algs[alg], data_size, data, buf);
    cc_copy(digest_size, digest, buf);
}

static size_t crypto_hmac_ctx_size(crypto_digest_alg_t alg) {
    return cchmac_di_size(crypto_digest_algs[alg]);
}

static void crypto_hmac_init(crypto_digest_alg_t alg,
                      void *ctx,
                      size_t ctx_size,
                      const void *key,
                      size_t key_size) {
    cc_client_crash(ctx_size != cchmac_di_size(crypto_digest_algs[alg]), "ctx_size != cchmac_di_size");
    cchmac_init(crypto_digest_algs[alg], (cchmac_ctx_t)ctx, key_size, key);
}

// pd: the rest of the hmac contract (rfc 2104 through cchmac)
static void crypto_hmac_update(crypto_digest_alg_t alg, void *ctx, size_t ctx_size, const void *data, size_t data_size)
{
    cc_client_crash(ctx_size != cchmac_di_size(crypto_digest_algs[alg]), "ctx_size != cchmac_di_size");
    cchmac_update(crypto_digest_algs[alg], (cchmac_ctx_t)ctx, data_size, data);
}

static void crypto_hmac_final_generate(crypto_digest_alg_t alg, void *ctx, size_t ctx_size, void *tag, size_t tag_size)
{
    uint8_t buf[DIGEST_MAX_OUTPUT_SIZE];

    cc_client_crash(ctx_size != cchmac_di_size(crypto_digest_algs[alg]), "ctx_size != cchmac_di_size");
    cc_client_crash(tag_size > crypto_digest_algs[alg]->output_size, "tag_size > output_size");
    cchmac_final(crypto_digest_algs[alg], (cchmac_ctx_t)ctx, buf);
    cc_copy(tag_size, tag, buf);
    cc_clear(sizeof(buf), buf);
}

static bool crypto_hmac_final_verify(crypto_digest_alg_t alg, void *ctx, size_t ctx_size, const void *tag, size_t tag_size)
{
    uint8_t buf[DIGEST_MAX_OUTPUT_SIZE];
    bool ok;

    cc_client_crash(ctx_size != cchmac_di_size(crypto_digest_algs[alg]), "ctx_size != cchmac_di_size");
    cc_client_crash(tag_size > crypto_digest_algs[alg]->output_size, "tag_size > output_size");
    cchmac_final(crypto_digest_algs[alg], (cchmac_ctx_t)ctx, buf);
    ok = cc_cmp_safe(tag_size, tag, buf) == 0;
    cc_clear(sizeof(buf), buf);
    return ok;
}

static void crypto_hmac_generate(crypto_digest_alg_t alg, const void *key, size_t key_size, const void *data, size_t data_size,
                          void *tag, size_t tag_size)
{
    uint8_t buf[DIGEST_MAX_OUTPUT_SIZE];

    cc_client_crash(tag_size > crypto_digest_algs[alg]->output_size, "tag_size > output_size");
    cchmac(crypto_digest_algs[alg], key_size, key, data_size, data, buf);
    cc_copy(tag_size, tag, buf);
    cc_clear(sizeof(buf), buf);
}

static bool crypto_hmac_verify(crypto_digest_alg_t alg, const void *key, size_t key_size, const void *data, size_t data_size,
                        const void *tag, size_t tag_size)
{
    uint8_t buf[DIGEST_MAX_OUTPUT_SIZE];
    bool ok;

    cc_client_crash(tag_size > crypto_digest_algs[alg]->output_size, "tag_size > output_size");
    cchmac(crypto_digest_algs[alg], key_size, key, data_size, data, buf);
    ok = cc_cmp_safe(tag_size, tag, buf) == 0;
    cc_clear(sizeof(buf), buf);
    return ok;
}

// pd: random handles are ccrng_state shaped, the kmem one is a lock-free integer-only chacha20 stream
struct kmem_rng {
    cc_error_t (*generate)(struct ccrng_state *rng, size_t nbytes, void *out);
    ccchacha20_ctx chacha;
};

static cc_error_t kmem_rng_generate(struct ccrng_state *rng, size_t nbytes, void *out)
{
    struct kmem_rng *k = (struct kmem_rng *)rng;
    cc_clear(nbytes, out);
    return ccchacha20_update(&k->chacha, nbytes, out, out);
}

static size_t crypto_random_kmem_ctx_size(void)
{
    return sizeof(struct kmem_rng);
}

static void crypto_random_kmem_init(crypto_random_ctx_t ctx)
{
    struct kmem_rng *k = ctx;
    uint8_t seed[32 + CCCHACHA20_NONCE_NBYTES];

    read_random(seed, sizeof(seed));
    ccchacha20_init(&k->chacha, seed);
    ccchacha20_setnonce(&k->chacha, seed + 32);
    ccchacha20_setcounter(&k->chacha, 0);
    k->generate = &kmem_rng_generate;
    cc_clear(sizeof(seed), seed);
}

static void crypto_random_generate(crypto_random_ctx_t ctx, void *random, size_t random_size)
{
    struct ccrng_state *rng = ctx;
    if (ccrng_generate(rng, random_size, random) != CCERR_OK) {
        cc_abort("crypto_random_generate: generator failed");
    }
}

static void crypto_random_uniform(crypto_random_ctx_t ctx, uint64_t bound, uint64_t *random)
{
    if (ccrng_uniform((struct ccrng_state *)ctx, bound, random) != CCERR_OK) {
        cc_abort("crypto_random_uniform: generator failed");
    }
}

#endif // __CC_DEPLOYMENT_IS_IN_RANGE(__MAC_13_0, __MAC_28_0)

void cc_kernel_populate_registration(void)
{
    corecrypto_registration_if.ccdigest_init_fn = &ccdigest_init;
    corecrypto_registration_if.ccdigest_update_fn = &ccdigest_update;
    corecrypto_registration_if.ccdigest_final_fn = &ccdigest_final;
    corecrypto_registration_if.ccdigest_fn = &ccdigest;

    corecrypto_registration_if.ccmd5_di = ccmd5_di();
    corecrypto_registration_if.ccsha1_di = ccsha1_di();
    corecrypto_registration_if.ccsha256_di = ccsha256_di();
    corecrypto_registration_if.ccsha384_di = ccsha384_di();
    corecrypto_registration_if.ccsha512_di = ccsha512_di();

    corecrypto_registration_if.cchmac_init_fn = &cchmac_init;
    corecrypto_registration_if.cchmac_update_fn = &cchmac_update;
    corecrypto_registration_if.cchmac_final_fn = (cchmac_final_fn_t)&cchmac_final;
    corecrypto_registration_if.cchmac_fn = (cchmac_fn_t)&cchmac;

    corecrypto_registration_if.ccaes_ecb_encrypt = ccaes_ecb_encrypt_mode();
    corecrypto_registration_if.ccaes_ecb_decrypt = ccaes_ecb_decrypt_mode();
    corecrypto_registration_if.ccaes_cbc_encrypt = ccaes_cbc_encrypt_mode();
    corecrypto_registration_if.ccaes_cbc_decrypt = ccaes_cbc_decrypt_mode();
    corecrypto_registration_if.ccaes_ctr_crypt = ccaes_ctr_crypt_mode();
    corecrypto_registration_if.ccaes_xts_encrypt = ccaes_xts_encrypt_mode();
    corecrypto_registration_if.ccaes_xts_decrypt = ccaes_xts_decrypt_mode();

    corecrypto_registration_if.ccaes_gcm_encrypt = ccaes_gcm_encrypt_mode();
    corecrypto_registration_if.ccaes_gcm_decrypt = ccaes_gcm_decrypt_mode();
    corecrypto_registration_if.ccgcm_init_with_iv_fn = &ccgcm_init_with_iv;
    corecrypto_registration_if.ccgcm_inc_iv_fn = &ccgcm_inc_iv;

    corecrypto_registration_if.ccchacha20poly1305_fns = &ccchacha20poly1305_kernel_fns;

    corecrypto_registration_if.ccdes_ecb_encrypt = ccdes_ecb_encrypt_mode();
    corecrypto_registration_if.ccdes_ecb_decrypt = ccdes_ecb_decrypt_mode();
    corecrypto_registration_if.ccdes_cbc_encrypt = ccdes_cbc_encrypt_mode();
    corecrypto_registration_if.ccdes_cbc_decrypt = ccdes_cbc_decrypt_mode();
    corecrypto_registration_if.cctdes_ecb_encrypt = ccdes3_ecb_encrypt_mode();
    corecrypto_registration_if.cctdes_ecb_decrypt = ccdes3_ecb_decrypt_mode();
    corecrypto_registration_if.cctdes_cbc_encrypt = ccdes3_cbc_encrypt_mode();
    corecrypto_registration_if.cctdes_cbc_decrypt = ccdes3_cbc_decrypt_mode();

#if __CC_DEPLOYMENT_IS_IN_RANGE(__MAC_10_10, __MAC_11_0)
    corecrypto_registration_if.ccrc4_info = ccrc4();
#endif  // __CC_DEPLOYMENT_IS_IN_RANGE(__MAC_10_10, __MAC_11_0)

#if __CC_DEPLOYMENT_IS_IN_RANGE(__MAC_10_10, __MAC_11_0)
    corecrypto_registration_if.ccblowfish_ecb_encrypt = ccblowfish_ecb_encrypt_mode();
    corecrypto_registration_if.ccblowfish_ecb_decrypt = ccblowfish_ecb_decrypt_mode();
    corecrypto_registration_if.cccast_ecb_encrypt = cccast_ecb_encrypt_mode();
    corecrypto_registration_if.cccast_ecb_decrypt = cccast_ecb_decrypt_mode();
#endif

    corecrypto_registration_if.ccdes_key_is_weak_fn = (ccdes_key_is_weak_fn_t)&ccdes_key_is_weak;
    corecrypto_registration_if.ccdes_key_set_odd_parity_fn = &ccdes_key_set_odd_parity;


    corecrypto_registration_if.ccpad_cts3_encrypt_fn = &ccpad_cts3_encrypt;
    corecrypto_registration_if.ccpad_cts3_decrypt_fn = &ccpad_cts3_decrypt;

    // in xnu, netkey/key.c uses ccrng for random key fill
    //         it's also used for swap encryption and decryption
    //         remind me to write the XTS implementation for that.
    corecrypto_registration_if.ccrng_fn = &ccrng;

    // these rsa routines are used for imageboot dmg validation (bsd/kern/chunklist.c through libkern/crypto/corecrypto_rsa.c)
    corecrypto_registration_if.ccrsa_make_pub_fn = &ccrsa_make_pub;
    corecrypto_registration_if.ccrsa_verify_pkcs1v15_fn = &ccrsa_verify_pkcs1v15;
    
#if 1 // pd: xnu 12377 always uses the crypto_digest/hmac/random contract
    crypto_digest_algs[CRYPTO_DIGEST_ALG_MD5] = ccmd5_di();
    crypto_digest_algs[CRYPTO_DIGEST_ALG_SHA1] = ccsha1_di();
    crypto_digest_algs[CRYPTO_DIGEST_ALG_SHA256] = ccsha256_di();
    crypto_digest_algs[CRYPTO_DIGEST_ALG_SHA384] = ccsha384_di();
    crypto_digest_algs[CRYPTO_DIGEST_ALG_SHA512] = ccsha512_di();
    
    corecrypto_registration_if.digest_ctx_size_fn = &crypto_digest_ctx_size;
    corecrypto_registration_if.digest_init_fn = &crypto_digest_init;
    corecrypto_registration_if.digest_update_fn = &crypto_digest_update;
    corecrypto_registration_if.digest_final_fn = &crypto_digest_final;
    corecrypto_registration_if.digest_fn = &crypto_digest;
    
    corecrypto_registration_if.hmac_ctx_size_fn = &crypto_hmac_ctx_size;
    corecrypto_registration_if.hmac_init_fn = &crypto_hmac_init;
    corecrypto_registration_if.hmac_update_fn = &crypto_hmac_update;
    corecrypto_registration_if.hmac_final_generate_fn = &crypto_hmac_final_generate;
    corecrypto_registration_if.hmac_final_verify_fn = &crypto_hmac_final_verify;
    corecrypto_registration_if.hmac_generate_fn = &crypto_hmac_generate;
    corecrypto_registration_if.hmac_verify_fn = &crypto_hmac_verify;

    corecrypto_registration_if.random_generate_fn = &crypto_random_generate;
    corecrypto_registration_if.random_uniform_fn = &crypto_random_uniform;
    corecrypto_registration_if.random_kmem_ctx_size_fn = &crypto_random_kmem_ctx_size;
    corecrypto_registration_if.random_kmem_init_fn = &crypto_random_kmem_init;
#endif // __CC_DEPLOYMENT_IS_IN_RANGE(__MAC_13_0, __MAC_28_0)
}

//
// KPRNG
//
struct cckprng_ctx kprng_ctx;

const struct cckprng_funcs kprng_funcs = {
    .init = cckprng_init,
    .initgen = cckprng_initgen,
    .reseed = cckprng_reseed,
    .refresh = cckprng_refresh,
    .generate = cckprng_generate,
    .init_with_getentropy = cckprng_init_with_getentropy,
};

// MARK: kmod entrypoints
kern_return_t corecrypto_start(kmod_info_t * ki, void *d)
{
    printf("corecrypto: neo-corecrypto (pd interim) loading\n");

    // known-answer self tests before anything is registered
    if (ccpost_validate() != CCERR_OK) {
        cc_abort("corecrypto: power-on self tests failed");
    }
    printf("corecrypto: self tests passed\n");

    cc_kernel_populate_registration();

    kern_return_t res = register_crypto_functions(&corecrypto_registration_if);
    if (res != KERN_SUCCESS) {
        cc_internal_crash(1, "well. this is awkward.");
    }
    
    // wire in kernel PRNG.
    register_and_init_prng(&kprng_ctx, &kprng_funcs);
    printf("corecrypto: kernel prng registered\n");

    return KERN_SUCCESS;
}

kern_return_t corecrypto_stop(kmod_info_t *ki, void *d)
{
    return KERN_SUCCESS;
}
