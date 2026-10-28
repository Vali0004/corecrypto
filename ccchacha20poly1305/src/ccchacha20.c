/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
// pd interim LLM-written code, experimental and not secure: unaudited, unfuzzed, no side-channel review

#include <corecrypto/cc_priv.h>
#include <corecrypto/ccchacha20poly1305_priv.h>

/*
 * Baesd off of pseudocode from RFC 7539,
 *
 * see here:
 * https://datatracker.ietf.org/doc/html/rfc7539
 */

#define CHACHA_QROUND(state, a, b, c, d)        \
    state[a] += state[b];                       \
    state[d] = cc_rol(state[d] ^ state[a], 16); \
    state[c] += state[d];                       \
    state[b] = cc_rol(state[b] ^ state[c], 12); \
    state[a] += state[b];                       \
    state[d] = cc_rol(state[d] ^ state[a], 8);  \
    state[c] += state[d];                       \
    state[b] = cc_rol(state[b] ^ state[c], 7);


//
// Initialise the keystream
//
cc_error_t ccchacha20_init(ccchacha20_ctx *ctx, const void *key) {
    // msvc is very particular regarding void pointers.
    const uint8_t *_key = (const uint8_t *)key;
    
    // constants
    ctx->state[0] = 0x61707865;
    ctx->state[1] = 0x3320646e;
    ctx->state[2] = 0x79622d32;
    ctx->state[3] = 0x6b206574;
    
    // absorb key into state
    cc_load32_le(ctx->state[4], _key);
    cc_load32_le(ctx->state[5], _key+4);
    cc_load32_le(ctx->state[6], _key+8);
    cc_load32_le(ctx->state[7], _key+12);
    cc_load32_le(ctx->state[8], _key+16);
    cc_load32_le(ctx->state[9], _key+20);
    cc_load32_le(ctx->state[10], _key+24);
    cc_load32_le(ctx->state[11], _key+28);
    
    return CCERR_OK;
}

cc_error_t ccchacha20_setcounter(ccchacha20_ctx *ctx, uint32_t counter) {
    ctx->state[12] = counter;
    ctx->leftover = 0;
    return CCERR_OK;
}

cc_error_t ccchacha20_setnonce(ccchacha20_ctx *ctx, const void *nonce) {
    // msvc is very particular regarding void pointers.
    const uint8_t *_nonce = (const uint8_t *)nonce;
    
    cc_load32_le(ctx->state[13], _nonce);
    cc_load32_le(ctx->state[14], _nonce+4);
    cc_load32_le(ctx->state[15], _nonce+8);
    
    return CCERR_OK;
}

// 20 rounds then the feed-forward add, serialised little-endian (rfc 8439 2.3)
cc_error_t _ccchacha20_block(ccchacha20_ctx *ctx) {
    uint32_t x[16];

    for (int i = 0; i < 16; i++) {
        x[i] = ctx->state[i];
    }

    for (int r = 20; r > 0; r -= 2) {
        CHACHA_QROUND(x, 0, 4, 8, 12);
        CHACHA_QROUND(x, 1, 5, 9, 13);
        CHACHA_QROUND(x, 2, 6, 10, 14);
        CHACHA_QROUND(x, 3, 7, 11, 15);
        CHACHA_QROUND(x, 0, 5, 10, 15);
        CHACHA_QROUND(x, 1, 6, 11, 12);
        CHACHA_QROUND(x, 2, 7, 8, 13);
        CHACHA_QROUND(x, 3, 4, 9, 14);
    }

    for (int i = 0; i < 16; i++) {
        uint32_t v = x[i] + ctx->state[i];
        ctx->buffer[4 * i] = (uint8_t)v;
        ctx->buffer[4 * i + 1] = (uint8_t)(v >> 8);
        ctx->buffer[4 * i + 2] = (uint8_t)(v >> 16);
        ctx->buffer[4 * i + 3] = (uint8_t)(v >> 24);
    }

    cc_clear(sizeof(x), x);
    return CCERR_OK;
}

// leftover counts keystream bytes already used from the buffered block (rfc 8439 2.4)
cc_error_t ccchacha20_update(ccchacha20_ctx *ctx, size_t nbytes, const void *in, void *out) {
    const uint8_t *p = (const uint8_t *)in;
    uint8_t *o = (uint8_t *)out;

    while (nbytes) {
        if (ctx->leftover == 0) {
            _ccchacha20_block(ctx);
            ctx->state[12]++;
        }

        size_t nb = CCCHACHA20_BLOCK_NBYTES - ctx->leftover;
        if (nb > nbytes) nb = nbytes;

        cc_xor(nb, o, p, ctx->buffer + ctx->leftover);
        p += nb;
        o += nb;
        nbytes -= nb;
        ctx->leftover = (ctx->leftover + nb) % CCCHACHA20_BLOCK_NBYTES;
    }

    return CCERR_OK;
}

cc_error_t ccchacha20_reset(ccchacha20_ctx *ctx) {
    ctx->leftover = 0;
    return ccchacha20_setcounter(ctx, 0);
}

cc_error_t ccchacha20_final(ccchacha20_ctx *ctx) {
    cc_clear(sizeof(*ctx), ctx);
    return CCERR_OK;
}

cc_error_t ccchacha20(const void *key,
                      const void *nonce,
                      uint32_t counter,
                      size_t nbytes,
                      const void *in,
                      void *out) {
    ccchacha20_ctx ctx;

    ccchacha20_init(&ctx, key);
    ccchacha20_setnonce(&ctx, nonce);
    ccchacha20_setcounter(&ctx, counter);
    ccchacha20_update(&ctx, nbytes, in, out);
    ccchacha20_final(&ctx);

    return CCERR_OK;
}
