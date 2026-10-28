/*
 * Copyright (C) 2026, PureDarwin contributors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CCKPRNG_H__
#define __CORECRYPTO_CCKPRNG_H__

#include <corecrypto/cc.h>
#include <corecrypto/ccdrbg.h>

CC_BEGIN_DECLS

// kernel prng contract with xnu's prng/random.h, the context is private to this library

#define CCKPRNG_SEED_NBYTES         32
#define CCKPRNG_ENTROPY_SIZE        64
#define CCKPRNG_GENERATE_MAX_NBYTES 256
#define CCKPRNG_MAX_GENS            256

typedef int32_t (*cckprng_getentropy)(size_t *entropy_nbytes, void *entropy, void *arg);
typedef cckprng_getentropy ccrng_fortuna_getentropy;

struct cckprng_gen {
    uint64_t epoch;
    bool init;
    struct ccdrbg_state *drbg;
};

struct cckprng_ctx {
    volatile uint32_t spin;
    uint64_t epoch;
    uint64_t refreshes;
    uint8_t key[32];
    cckprng_getentropy getentropy;
    void *getentropy_arg;
    unsigned max_ngens;
    struct ccdrbg_info drbg_info;
    struct ccdrbg_nistctr_custom drbg_custom;
    uint8_t *drbg_states;
    struct cckprng_gen gens[CCKPRNG_MAX_GENS];
};

struct cckprng_funcs {
    void (*init)(struct cckprng_ctx *ctx, size_t seed_nbytes, const void *seed, size_t nonce_nbytes, const void *nonce,
                 cckprng_getentropy getentropy, void *getentropy_arg);
    void (*initgen)(struct cckprng_ctx *ctx, unsigned gen_idx);
    void (*reseed)(struct cckprng_ctx *ctx, size_t nbytes, const void *seed);
    void (*refresh)(struct cckprng_ctx *ctx);
    void (*generate)(struct cckprng_ctx *ctx, unsigned gen_idx, size_t nbytes, void *out);
    void (*init_with_getentropy)(struct cckprng_ctx *ctx, unsigned max_ngens, size_t seed_nbytes, const void *seed,
                                 size_t nonce_nbytes, const void *nonce, cckprng_getentropy getentropy, void *getentropy_arg);
};

CC_EXPORT void cckprng_init(struct cckprng_ctx *ctx, size_t seed_nbytes, const void *seed, size_t nonce_nbytes, const void *nonce,
                            cckprng_getentropy getentropy, void *getentropy_arg);
CC_EXPORT void cckprng_init_with_getentropy(struct cckprng_ctx *ctx, unsigned max_ngens, size_t seed_nbytes, const void *seed,
                                            size_t nonce_nbytes, const void *nonce, cckprng_getentropy getentropy, void *getentropy_arg);
CC_EXPORT void cckprng_initgen(struct cckprng_ctx *ctx, unsigned gen_idx);
CC_EXPORT void cckprng_reseed(struct cckprng_ctx *ctx, size_t nbytes, const void *seed);
CC_EXPORT void cckprng_refresh(struct cckprng_ctx *ctx);
CC_EXPORT void cckprng_generate(struct cckprng_ctx *ctx, unsigned gen_idx, size_t nbytes, void *out);

CC_END_DECLS

#endif /* __CORECRYPTO_CCKPRNG_H__ */
