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

// constant-time check of the pad bytes, returns the data bytes left in the block or 0 when bad (rfc 5652 6.3)
size_t ccpad_pkcs7_decode(const size_t block_size, const uint8_t *last_block)
{
    uint8_t p = last_block[block_size - 1];
    unsigned bad = (unsigned)(p == 0) | (unsigned)(p > block_size);

    for (size_t i = 0; i < block_size; i++) {
        // bytes at index >= block_size - p must equal p
        unsigned in_pad = (unsigned)(i >= block_size - (size_t)p);
        bad |= in_pad & (unsigned)(last_block[i] != p);
    }

    size_t keep = block_size - (size_t)p;
    size_t mask = (size_t)0 - (size_t)(bad == 0);
    return keep & mask;
}

size_t ccpad_pkcs7_encrypt(const struct ccmode_cbc *cbc, cccbc_ctx *ctx, cccbc_iv *iv, size_t nbytes, const void *in, void *out)
{
    size_t bs = cbc->block_size;
    size_t full = nbytes / bs;
    size_t rem = nbytes - full * bs;
    uint8_t last[CCMODE_MAX_BLOCK_SIZE];
    const uint8_t *src = in;
    uint8_t *dst = out;

    if (full) {
        cbc->cbc(ctx, iv, full, src, dst);
    }

    // pad with k - (l mod k) bytes each of that value
    uint8_t pv = (uint8_t)(bs - rem);
    cc_copy(rem, last, src + full * bs);
    memset(last + rem, pv, bs - rem);
    cbc->cbc(ctx, iv, 1, last, dst + full * bs);
    cc_clear(sizeof(last), last);

    return (full + 1) * bs;
}

size_t ccpad_pkcs7_decrypt(const struct ccmode_cbc *cbc, cccbc_ctx *ctx, cccbc_iv *iv, size_t nbytes, const void *in, void *out)
{
    size_t bs = cbc->block_size;
    size_t nblocks = nbytes / bs;
    uint8_t *dst = out;

    if (nblocks == 0) return 0;

    cbc->cbc(ctx, iv, nblocks, in, out);

    // a bad pad drops the whole last block and is not reported separately
    return (nblocks - 1) * bs + ccpad_pkcs7_decode(bs, dst + (nblocks - 1) * bs);
}

size_t ccpad_pkcs7_ecb_encrypt(const struct ccmode_ecb *ecb, ccecb_ctx *ctx, size_t nbytes, const void *in, void *out)
{
    size_t bs = ecb->block_size;
    size_t full = nbytes / bs;
    size_t rem = nbytes - full * bs;
    uint8_t last[CCMODE_MAX_BLOCK_SIZE];
    const uint8_t *src = in;
    uint8_t *dst = out;

    if (full) {
        ecb->ecb(ctx, full, src, dst);
    }

    uint8_t pv = (uint8_t)(bs - rem);
    cc_copy(rem, last, src + full * bs);
    memset(last + rem, pv, bs - rem);
    ecb->ecb(ctx, 1, last, dst + full * bs);
    cc_clear(sizeof(last), last);

    return (full + 1) * bs;
}

size_t ccpad_pkcs7_ecb_decrypt(const struct ccmode_ecb *ecb, ccecb_ctx *ecb_key, size_t nbytes, const void *in, void *out)
{
    size_t bs = ecb->block_size;
    size_t nblocks = nbytes / bs;
    uint8_t *dst = out;

    if (nblocks == 0) return 0;

    ecb->ecb(ecb_key, nblocks, in, out);
    return (nblocks - 1) * bs + ccpad_pkcs7_decode(bs, dst + (nblocks - 1) * bs);
}
