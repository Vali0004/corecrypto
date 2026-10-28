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

// poly1305 over 2^130 - 5 with 26-bit limbs (rfc 8439 2.5)

static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

cc_error_t ccpoly1305_init(ccpoly1305_ctx *ctx, const void *key)
{
    const uint8_t *k = key;

    // clamp r (rfc 8439 2.5.1)
    ctx->r0 = (le32(k + 0)) & 0x3ffffff;
    ctx->r1 = (le32(k + 3) >> 2) & 0x3ffff03;
    ctx->r2 = (le32(k + 6) >> 4) & 0x3ffc0ff;
    ctx->r3 = (le32(k + 9) >> 6) & 0x3f03fff;
    ctx->r4 = (le32(k + 12) >> 8) & 0x00fffff;

    ctx->s1 = ctx->r1 * 5;
    ctx->s2 = ctx->r2 * 5;
    ctx->s3 = ctx->r3 * 5;
    ctx->s4 = ctx->r4 * 5;

    ctx->h0 = ctx->h1 = ctx->h2 = ctx->h3 = ctx->h4 = 0;
    ctx->buf_used = 0;
    cc_copy(16, ctx->key, k + 16);
    return CCERR_OK;
}

static void poly_blocks(ccpoly1305_ctx *ctx, const uint8_t *m, size_t nblocks, uint32_t hibit)
{
    uint32_t r0 = ctx->r0, r1 = ctx->r1, r2 = ctx->r2, r3 = ctx->r3, r4 = ctx->r4;
    uint32_t s1 = ctx->s1, s2 = ctx->s2, s3 = ctx->s3, s4 = ctx->s4;
    uint32_t h0 = ctx->h0, h1 = ctx->h1, h2 = ctx->h2, h3 = ctx->h3, h4 = ctx->h4;

    while (nblocks--) {
        // h += m with the 2^128 bit, then h *= r mod p
        h0 += (le32(m + 0)) & 0x3ffffff;
        h1 += (le32(m + 3) >> 2) & 0x3ffffff;
        h2 += (le32(m + 6) >> 4) & 0x3ffffff;
        h3 += (le32(m + 9) >> 6) & 0x3ffffff;
        h4 += (le32(m + 12) >> 8) | hibit;

        uint64_t d0 = (uint64_t)h0 * r0 + (uint64_t)h1 * s4 + (uint64_t)h2 * s3 + (uint64_t)h3 * s2 + (uint64_t)h4 * s1;
        uint64_t d1 = (uint64_t)h0 * r1 + (uint64_t)h1 * r0 + (uint64_t)h2 * s4 + (uint64_t)h3 * s3 + (uint64_t)h4 * s2;
        uint64_t d2 = (uint64_t)h0 * r2 + (uint64_t)h1 * r1 + (uint64_t)h2 * r0 + (uint64_t)h3 * s4 + (uint64_t)h4 * s3;
        uint64_t d3 = (uint64_t)h0 * r3 + (uint64_t)h1 * r2 + (uint64_t)h2 * r1 + (uint64_t)h3 * r0 + (uint64_t)h4 * s4;
        uint64_t d4 = (uint64_t)h0 * r4 + (uint64_t)h1 * r3 + (uint64_t)h2 * r2 + (uint64_t)h3 * r1 + (uint64_t)h4 * r0;

        uint32_t c;
        c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffff;
        d1 += c; c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffff;
        d2 += c; c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffff;
        d3 += c; c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffff;
        d4 += c; c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffff;
        h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
        h1 += c;

        m += 16;
    }

    ctx->h0 = h0; ctx->h1 = h1; ctx->h2 = h2; ctx->h3 = h3; ctx->h4 = h4;
}

cc_error_t ccpoly1305_update(ccpoly1305_ctx *ctx, size_t nbytes, const void *in)
{
    const uint8_t *m = in;

    if (ctx->buf_used) {
        size_t take = 16 - ctx->buf_used;
        if (take > nbytes) take = nbytes;
        cc_copy(take, ctx->buf + ctx->buf_used, m);
        ctx->buf_used += take;
        m += take;
        nbytes -= take;
        if (ctx->buf_used < 16) return CCERR_OK;
        poly_blocks(ctx, ctx->buf, 1, 1u << 24);
        ctx->buf_used = 0;
    }

    if (nbytes >= 16) {
        size_t n = nbytes / 16;
        poly_blocks(ctx, m, n, 1u << 24);
        m += n * 16;
        nbytes -= n * 16;
    }

    if (nbytes) {
        cc_copy(nbytes, ctx->buf, m);
        ctx->buf_used = nbytes;
    }
    return CCERR_OK;
}

// tag = (h mod p) + s mod 2^128 (rfc 8439 2.5.1)
cc_error_t ccpoly1305_final(ccpoly1305_ctx *ctx, void *tag)
{
    uint8_t *out = tag;

    if (ctx->buf_used) {
        // a short last block gets its 0x01 byte inline, no 2^128 bit
        ctx->buf[ctx->buf_used] = 1;
        for (size_t i = ctx->buf_used + 1; i < 16; i++) ctx->buf[i] = 0;
        poly_blocks(ctx, ctx->buf, 1, 0);
    }

    uint32_t h0 = ctx->h0, h1 = ctx->h1, h2 = ctx->h2, h3 = ctx->h3, h4 = ctx->h4, c;

    c = h1 >> 26; h1 &= 0x3ffffff;
    h2 += c; c = h2 >> 26; h2 &= 0x3ffffff;
    h3 += c; c = h3 >> 26; h3 &= 0x3ffffff;
    h4 += c; c = h4 >> 26; h4 &= 0x3ffffff;
    h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
    h1 += c;

    // g = h + 5 - 2^130, keep g when it did not borrow
    uint32_t g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    uint32_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    uint32_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    uint32_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    uint32_t g4 = h4 + c - (1u << 26);

    uint32_t mask = (g4 >> 31) - 1;
    h0 = (h0 & ~mask) | (g0 & mask);
    h1 = (h1 & ~mask) | (g1 & mask);
    h2 = (h2 & ~mask) | (g2 & mask);
    h3 = (h3 & ~mask) | (g3 & mask);
    h4 = (h4 & ~mask) | (g4 & mask);

    uint32_t w0 = h0 | (h1 << 26);
    uint32_t w1 = (h1 >> 6) | (h2 << 20);
    uint32_t w2 = (h2 >> 12) | (h3 << 14);
    uint32_t w3 = (h3 >> 18) | (h4 << 8);

    uint64_t f;
    f = (uint64_t)w0 + le32(ctx->key + 0); w0 = (uint32_t)f;
    f = (uint64_t)w1 + le32(ctx->key + 4) + (f >> 32); w1 = (uint32_t)f;
    f = (uint64_t)w2 + le32(ctx->key + 8) + (f >> 32); w2 = (uint32_t)f;
    f = (uint64_t)w3 + le32(ctx->key + 12) + (f >> 32); w3 = (uint32_t)f;

    uint32_t w[4] = { w0, w1, w2, w3 };
    for (int i = 0; i < 4; i++) {
        out[4 * i] = (uint8_t)w[i];
        out[4 * i + 1] = (uint8_t)(w[i] >> 8);
        out[4 * i + 2] = (uint8_t)(w[i] >> 16);
        out[4 * i + 3] = (uint8_t)(w[i] >> 24);
    }

    cc_clear(sizeof(*ctx), ctx);
    return CCERR_OK;
}

cc_error_t ccpoly1305(const void *key, size_t nbytes, const void *in, void *out)
{
    ccpoly1305_ctx ctx;
    ccpoly1305_init(&ctx, key);
    ccpoly1305_update(&ctx, nbytes, in);
    return ccpoly1305_final(&ctx, out);
}
