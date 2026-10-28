/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
// pd interim LLM-written code, experimental and not secure: unaudited, unfuzzed, no side-channel review

#include <corecrypto/cc_priv.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/ccdrbg.h>
#include <corecrypto/ccrng.h>
#include <corecrypto/ccrng_system.h>

#if CC_PLATFORM_XNU

#include <sys/random.h>

// the kernel's read_random is already backed by the registered kprng
static cc_error_t ccrng_kernel_generate(struct ccrng_state *state, size_t nbytes, void *out)
{
    uint8_t *p = out;
    (void)state;

    while (nbytes) {
        u_int take = nbytes > 0x10000 ? 0x10000 : (u_int)nbytes;
        read_random(p, take);
        p += take;
        nbytes -= take;
    }
    return CCERR_OK;
}

static struct ccrng_state ccrng_kernel_state = { .generate = &ccrng_kernel_generate };

struct ccrng_state *ccrng(cc_error_t *err)
{
    if (err) *err = CCERR_OK;
    return &ccrng_kernel_state;
}

#else

#include <unistd.h>
#include <sys/random.h>
#if CC_PLATFORM_DARWIN
#include <os/lock.h>
#else
#include <pthread.h>
#endif

// ctr_drbg with aes-256 and a derivation function, seeded from getentropy (sp 800-90a 10.2.1)
struct ccrng_crypto_rng {
    bool did_init;
    pid_t pid;
#if CC_PLATFORM_DARWIN
    os_unfair_lock lock;
#else
    pthread_mutex_t lock;
#endif
    struct ccdrbg_info drbg_info;
    struct ccdrbg_nistctr_custom drbg_custom;
    struct ccdrbg_df_bc_ctx drbg_df_bc_ctx;
    uint64_t drbg_state_buffer[256];
    struct ccdrbg_state *drbg_state;
    struct ccrng_state rng_state;
};

static cc_error_t ccrng_crypto_rng_generate(struct ccrng_state *state, size_t nbytes, void *out);

static struct ccrng_crypto_rng ccrng_global = {
    .did_init = false,
#if CC_PLATFORM_DARWIN
    .lock = OS_UNFAIR_LOCK_INIT,
#else
    .lock = PTHREAD_MUTEX_INITIALIZER,
#endif
    .rng_state = { .generate = &ccrng_crypto_rng_generate },
};

static void rng_lock(void)
{
#if CC_PLATFORM_DARWIN
    os_unfair_lock_lock(&ccrng_global.lock);
#else
    pthread_mutex_lock(&ccrng_global.lock);
#endif
}

static void rng_unlock(void)
{
#if CC_PLATFORM_DARWIN
    os_unfair_lock_unlock(&ccrng_global.lock);
#else
    pthread_mutex_unlock(&ccrng_global.lock);
#endif
}

static cc_error_t rng_entropy(size_t nbytes, void *buf)
{
    // getentropy hands out at most 256 bytes per call
    uint8_t *p = buf;
    while (nbytes) {
        size_t take = nbytes > 256 ? 256 : nbytes;
        if (getentropy(p, take) != 0) return CCERR_OUT_OF_ENTROPY;
        p += take;
        nbytes -= take;
    }
    return CCERR_OK;
}

// instantiate, and instantiate again in a forked child so it never repeats the parent's stream
static cc_error_t rng_seed_locked(void)
{
    uint8_t entropy[48], nonce[16];
    pid_t pid = getpid();
    cc_error_t err;

    if (ccrng_global.did_init && ccrng_global.pid == pid) return CCERR_OK;

    if (!ccrng_global.did_init) {
        err = ccdrbg_df_bc_init(&ccrng_global.drbg_df_bc_ctx, ccaes_cbc_encrypt_mode(), CCAES_KEY_SIZE_256);
        if (err) return err;

        ccrng_global.drbg_custom.ctr = ccaes_ctr_crypt_mode();
        ccrng_global.drbg_custom.key_length = CCAES_KEY_SIZE_256;
        ccrng_global.drbg_custom.strictFIPS = true;
        ccrng_global.drbg_custom.df_ctx = (ccdrbg_df_ctx_t *)&ccrng_global.drbg_df_bc_ctx;
        ccdrbg_factory_nistctr(&ccrng_global.drbg_info, &ccrng_global.drbg_custom);

        if (ccrng_global.drbg_info.size == 0 || ccrng_global.drbg_info.size > sizeof(ccrng_global.drbg_state_buffer)) {
            return CCERR_INTERNAL;
        }
        ccrng_global.drbg_state = (struct ccdrbg_state *)ccrng_global.drbg_state_buffer;
    }

    err = rng_entropy(sizeof(entropy), entropy);
    if (err == 0) err = rng_entropy(sizeof(nonce), nonce);
    if (err == 0) {
        err = ccdrbg_init(&ccrng_global.drbg_info, ccrng_global.drbg_state,
                          sizeof(entropy), entropy, sizeof(nonce), nonce,
                          sizeof("corecrypto rng") - 1, "corecrypto rng");
    }

    cc_clear(sizeof(entropy), entropy);
    cc_clear(sizeof(nonce), nonce);
    if (err) return err;

    ccrng_global.pid = pid;
    ccrng_global.did_init = true;
    return CCERR_OK;
}

static cc_error_t rng_reseed_locked(void)
{
    uint8_t entropy[48];
    cc_error_t err = rng_entropy(sizeof(entropy), entropy);
    if (err == 0) err = ccdrbg_reseed(&ccrng_global.drbg_info, ccrng_global.drbg_state, sizeof(entropy), entropy, 0, NULL);
    cc_clear(sizeof(entropy), entropy);
    return err;
}

static cc_error_t ccrng_crypto_rng_generate(struct ccrng_state *state, size_t nbytes, void *out)
{
    uint8_t *p = out;
    cc_error_t err;
    (void)state;

    rng_lock();
    err = rng_seed_locked();

    while (err == CCERR_OK && nbytes) {
        // stay well under the per-request limit (sp 800-90a table 3)
        size_t take = nbytes > 4096 ? 4096 : nbytes;

        err = ccdrbg_generate(&ccrng_global.drbg_info, ccrng_global.drbg_state, take, p, 0, NULL);
        if (err == CCDRBG_STATUS_NEED_RESEED) {
            err = rng_reseed_locked();
            continue;
        }
        p += take;
        nbytes -= take;
    }
    rng_unlock();

    if (err) cc_clear(nbytes, p);
    return err;
}

struct ccrng_state *ccrng(cc_error_t *err)
{
    cc_error_t rc;

    rng_lock();
    rc = rng_seed_locked();
    rng_unlock();

    if (err) *err = rc;
    return rc ? NULL : &ccrng_global.rng_state;
}

#endif

// draw from [0, bound) by masking to the next power of two and rejecting (no modulo bias)
int ccrng_uniform(struct ccrng_state *rng, uint64_t bound, uint64_t *rand)
{
    if (bound == 0) return CCERR_PARAMETER;

    uint64_t mask = bound - 1;
    mask |= mask >> 1;
    mask |= mask >> 2;
    mask |= mask >> 4;
    mask |= mask >> 8;
    mask |= mask >> 16;
    mask |= mask >> 32;

    for (int tries = 0; tries < 256; tries++) {
        uint64_t v;
        int rc = ccrng_generate(rng, sizeof(v), &v);
        if (rc) return rc;
        v &= mask;
        if (v < bound) {
            *rand = v;
            return CCERR_OK;
        }
    }
    return CCERR_INTERNAL;
}

static int ccrng_system_generate(struct ccrng_state *rng, size_t outlen, void *out)
{
    cc_error_t err;
    struct ccrng_state *global = ccrng(&err);
    (void)rng;
    if (global == NULL) return err;
    return ccrng_generate(global, outlen, out);
}

int ccrng_system_init(struct ccrng_system_state *rng)
{
    rng->generate = &ccrng_system_generate;
    rng->fd = -1;
    return CCERR_OK;
}

void ccrng_system_done(struct ccrng_system_state *rng)
{
    rng->fd = -1;
}
