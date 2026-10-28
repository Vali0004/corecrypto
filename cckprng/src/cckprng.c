/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
// pd interim LLM-written code, experimental and not secure: unaudited, unfuzzed, no side-channel review

#include <corecrypto/cc_priv.h>
#include <corecrypto/cc_memory.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/cckprng.h>

// one hashed root key fed by seeds and kernel entropy, and one ctr_drbg per generator (cpu)
// that rekeys from the root whenever the root has moved on (sp 800-90a 10.2.1, no df, aes-256)

#define CCKPRNG_REFRESH_INTERVAL    64
#define CCKPRNG_MIN_SAMPLES         32

static void kprng_lock(struct cckprng_ctx *ctx)
{
    while (__atomic_exchange_n(&ctx->spin, 1, __ATOMIC_ACQUIRE)) {
        while (__atomic_load_n(&ctx->spin, __ATOMIC_RELAXED)) { }
    }
}

static void kprng_unlock(struct cckprng_ctx *ctx)
{
    __atomic_store_n(&ctx->spin, 0, __ATOMIC_RELEASE);
}

// key = sha-256(key || tag || data), called with the lock held
static void kprng_mix_locked(struct cckprng_ctx *ctx, uint8_t tag, size_t nbytes, const void *data)
{
    const struct ccdigest_info *di = ccsha256_di();
    ccdigest_di_decl(di, dctx);

    ccdigest_init(di, dctx);
    ccdigest_update(di, dctx, sizeof(ctx->key), ctx->key);
    ccdigest_update(di, dctx, 1, &tag);
    ccdigest_update(di, dctx, nbytes, data);
    ccdigest_final(di, dctx, ctx->key);
    ccdigest_di_clear(di, dctx);

    ctx->epoch++;
}

void cckprng_init_with_getentropy(struct cckprng_ctx *ctx, unsigned max_ngens, size_t seed_nbytes, const void *seed,
                                  size_t nonce_nbytes, const void *nonce, cckprng_getentropy getentropy, void *getentropy_arg)
{
    cc_clear(sizeof(*ctx), ctx);

    if (max_ngens == 0 || max_ngens > CCKPRNG_MAX_GENS) max_ngens = CCKPRNG_MAX_GENS;
    ctx->max_ngens = max_ngens;
    ctx->getentropy = getentropy;
    ctx->getentropy_arg = getentropy_arg;

    ctx->drbg_custom.ctr = ccaes_ctr_crypt_mode();
    ctx->drbg_custom.key_length = CCAES_KEY_SIZE_256;
    ctx->drbg_custom.strictFIPS = false;
    ctx->drbg_custom.df_ctx = NULL;
    ccdrbg_factory_nistctr(&ctx->drbg_info, &ctx->drbg_custom);

    size_t stride = (ctx->drbg_info.size + 15) & ~(size_t)15;
    ctx->drbg_states = cc_heap_allocate(stride * max_ngens);
    cc_clear(stride * max_ngens, ctx->drbg_states);
    for (unsigned i = 0; i < max_ngens; i++) {
        ctx->gens[i].drbg = (struct ccdrbg_state *)(ctx->drbg_states + stride * i);
    }

    kprng_mix_locked(ctx, 's', seed_nbytes, seed);
    kprng_mix_locked(ctx, 'n', nonce_nbytes, nonce);
}

void cckprng_init(struct cckprng_ctx *ctx, size_t seed_nbytes, const void *seed, size_t nonce_nbytes, const void *nonce,
                  cckprng_getentropy getentropy, void *getentropy_arg)
{
    cckprng_init_with_getentropy(ctx, 64, seed_nbytes, seed, nonce_nbytes, nonce, getentropy, getentropy_arg);
}

void cckprng_initgen(struct cckprng_ctx *ctx, unsigned gen_idx)
{
    if (gen_idx >= ctx->max_ngens) cc_abort("cckprng_initgen: generator index out of range");
    ctx->gens[gen_idx].init = true;
    ctx->gens[gen_idx].epoch = 0;
}

void cckprng_reseed(struct cckprng_ctx *ctx, size_t nbytes, const void *seed)
{
    kprng_lock(ctx);
    kprng_mix_locked(ctx, 'r', nbytes, seed);
    kprng_unlock(ctx);
}

// pull kernel entropy now and then, and only fold it in once enough samples arrived
void cckprng_refresh(struct cckprng_ctx *ctx)
{
    uint8_t buf[CCKPRNG_ENTROPY_SIZE];
    size_t nbytes = sizeof(buf);

    if (ctx->getentropy == NULL) return;
    if ((__atomic_fetch_add(&ctx->refreshes, 1, __ATOMIC_RELAXED) % CCKPRNG_REFRESH_INTERVAL) != 0) return;

    int32_t nsamples = ctx->getentropy(&nbytes, buf, ctx->getentropy_arg);
    if (nsamples >= CCKPRNG_MIN_SAMPLES && nbytes > 0 && nbytes <= sizeof(buf)) {
        kprng_lock(ctx);
        kprng_mix_locked(ctx, 'e', nbytes, buf);
        kprng_unlock(ctx);
    }
    cc_clear(sizeof(buf), buf);
}

void cckprng_generate(struct cckprng_ctx *ctx, unsigned gen_idx, size_t nbytes, void *out)
{
    if (gen_idx >= ctx->max_ngens || !ctx->gens[gen_idx].init) cc_abort("cckprng_generate: generator not initialised");
    if (nbytes > CCKPRNG_GENERATE_MAX_NBYTES) cc_abort("cckprng_generate: request too large");

    struct cckprng_gen *g = &ctx->gens[gen_idx];

    // each generator derives its own 48-byte seed from the root key, its index and the epoch
    if (g->epoch != __atomic_load_n(&ctx->epoch, __ATOMIC_ACQUIRE)) {
        const struct ccdigest_info *di = ccsha256_di();
        uint8_t material[64];
        uint64_t epoch;
        ccdigest_di_decl(di, dctx);

        kprng_lock(ctx);
        epoch = ctx->epoch;
        for (uint8_t half = 0; half < 2; half++) {
            ccdigest_init(di, dctx);
            ccdigest_update(di, dctx, sizeof(ctx->key), ctx->key);
            ccdigest_update(di, dctx, 1, &half);
            ccdigest_update(di, dctx, sizeof(gen_idx), &gen_idx);
            ccdigest_update(di, dctx, sizeof(epoch), &epoch);
            ccdigest_final(di, dctx, material + 32 * half);
        }
        kprng_unlock(ctx);
        ccdigest_di_clear(di, dctx);

        if (g->epoch == 0) {
            ccdrbg_init(&ctx->drbg_info, g->drbg, 48, material, 0, NULL, 0, NULL);
        } else {
            ccdrbg_reseed(&ctx->drbg_info, g->drbg, 48, material, 0, NULL);
        }
        g->epoch = epoch;
        cc_clear(sizeof(material), material);
    }

    if (nbytes && ccdrbg_generate(&ctx->drbg_info, g->drbg, nbytes, out, 0, NULL) != CCDRBG_STATUS_OK) {
        cc_abort("cckprng_generate: drbg failure");
    }
}
