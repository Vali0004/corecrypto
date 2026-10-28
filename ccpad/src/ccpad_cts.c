/*
 * Copyright (C) 2026, PureDarwin contributors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

// pd interim LLM-written code, experimental and not secure: unaudited, unfuzzed, no side-channel review
#include <corecrypto/cc_priv.h>
#include <corecrypto/ccpad.h>

// ciphertext stealing over cbc (sp 800-38a addendum, cbc-cs1/cs2/cs3)
// raw block ops reuse the cbc mode with a zero iv

static size_t cts_encrypt(const struct ccmode_cbc *cbc, cccbc_ctx *ctx, cccbc_iv *iv, size_t nbytes, const void *in, void *out, int variant)
{
    size_t bs = cbc->block_size;
    const uint8_t *src = in;
    uint8_t *dst = out;
    uint8_t cn1[CCMODE_MAX_BLOCK_SIZE], last[CCMODE_MAX_BLOCK_SIZE], cn[CCMODE_MAX_BLOCK_SIZE];

    if (nbytes < bs) return 0;
    if (nbytes == bs) {
        cbc->cbc(ctx, iv, 1, src, dst);
        return nbytes;
    }

    size_t d = nbytes % bs;
    if (d == 0) d = bs;
    size_t head = (nbytes - d - bs) / bs;

    if (head) {
        cbc->cbc(ctx, iv, head, src, dst);
    }
    src += head * bs;
    dst += head * bs;

    // c_(n-1)' from the last full block, c_n from the zero-padded tail
    cbc->cbc(ctx, iv, 1, src, cn1);
    cc_clear(bs, last);
    cc_copy(d, last, src + bs);
    cbc->cbc(ctx, iv, 1, last, cn);

    // cs1 keeps the order, cs3 always swaps, cs2 swaps only when the tail is partial
    bool swap = (variant == 3) || (variant == 2 && d != bs);
    if (swap) {
        cc_copy(bs, dst, cn);
        cc_copy(d, dst + bs, cn1);
    } else {
        cc_copy(d, dst, cn1);
        cc_copy(bs, dst + d, cn);
    }

    cc_clear(bs, cn1);
    cc_clear(bs, last);
    cc_clear(bs, cn);
    return nbytes;
}

static size_t cts_decrypt(const struct ccmode_cbc *cbc, cccbc_ctx *ctx, cccbc_iv *iv, size_t nbytes, const void *in, void *out, int variant)
{
    size_t bs = cbc->block_size;
    const uint8_t *src = in;
    uint8_t *dst = out;
    uint8_t cn1[CCMODE_MAX_BLOCK_SIZE], cn[CCMODE_MAX_BLOCK_SIZE], z[CCMODE_MAX_BLOCK_SIZE], prev[CCMODE_MAX_BLOCK_SIZE];

    if (nbytes < bs) return 0;
    if (nbytes == bs) {
        cbc->cbc(ctx, iv, 1, src, dst);
        return nbytes;
    }

    size_t d = nbytes % bs;
    if (d == 0) d = bs;
    size_t head = (nbytes - d - bs) / bs;

    if (head) {
        cbc->cbc(ctx, iv, head, src, dst);
    }
    src += head * bs;
    dst += head * bs;
    cc_copy(bs, prev, iv);

    bool swap = (variant == 3) || (variant == 2 && d != bs);
    const uint8_t *partial;
    if (swap) {
        cc_copy(bs, cn, src);
        partial = src + bs;
    } else {
        partial = src;
        cc_copy(bs, cn, src + d);
    }

    // z = d(c_n) = (p_n || 0) xor c_(n-1)', the tail of z completes c_(n-1)'
    {
        // cbc decrypt with a zero iv is the raw block decrypt
        uint8_t zero[CCMODE_MAX_BLOCK_SIZE] = { 0 };
        cbc->cbc(ctx, (cccbc_iv *)zero, 1, cn, z);
    }

    cc_copy(d, cn1, partial);
    cc_copy(bs - d, cn1 + d, z + d);

    uint8_t pn[CCMODE_MAX_BLOCK_SIZE];
    cc_xor(d, pn, z, cn1);

    // p_(n-1) = d(c_(n-1)') xor previous chaining block
    cc_copy(bs, iv, prev);
    cbc->cbc(ctx, iv, 1, cn1, dst);
    cc_copy(d, dst + bs, pn);

    // the next chaining value is c_n
    cc_copy(bs, iv, cn);

    cc_clear(bs, cn1);
    cc_clear(bs, cn);
    cc_clear(bs, z);
    cc_clear(bs, pn);
    return nbytes;
}

size_t ccpad_cts1_encrypt(const struct ccmode_cbc *cbc, cccbc_ctx *ctx, cccbc_iv *iv, size_t nbytes, const void *in, void *out)
{
    return cts_encrypt(cbc, ctx, iv, nbytes, in, out, 1);
}

size_t ccpad_cts1_decrypt(const struct ccmode_cbc *cbc, cccbc_ctx *ctx, cccbc_iv *iv, size_t nbytes, const void *in, void *out)
{
    return cts_decrypt(cbc, ctx, iv, nbytes, in, out, 1);
}

size_t ccpad_cts2_encrypt(const struct ccmode_cbc *cbc, cccbc_ctx *ctx, cccbc_iv *iv, size_t nbytes, const void *in, void *out)
{
    return cts_encrypt(cbc, ctx, iv, nbytes, in, out, 2);
}

size_t ccpad_cts2_decrypt(const struct ccmode_cbc *cbc, cccbc_ctx *ctx, cccbc_iv *iv, size_t nbytes, const void *in, void *out)
{
    return cts_decrypt(cbc, ctx, iv, nbytes, in, out, 2);
}

size_t ccpad_cts3_encrypt(const struct ccmode_cbc *cbc, cccbc_ctx *ctx, cccbc_iv *iv, size_t nbytes, const void *in, void *out)
{
    return cts_encrypt(cbc, ctx, iv, nbytes, in, out, 3);
}

size_t ccpad_cts3_decrypt(const struct ccmode_cbc *cbc, cccbc_ctx *ctx, cccbc_iv *iv, size_t nbytes, const void *in, void *out)
{
    return cts_decrypt(cbc, ctx, iv, nbytes, in, out, 3);
}
