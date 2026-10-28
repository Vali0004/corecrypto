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

// xts ciphertext stealing for a trailing partial block (sp 800-38e, ieee 1619 5.3.2 and 5.4.2)

void ccpad_xts_encrypt(const struct ccmode_xts *xts, ccxts_ctx *ctx, ccxts_tweak *tweak, size_t nbytes, const void *in, void *out)
{
    size_t bs = xts->block_size;
    size_t full = nbytes / bs;
    size_t r = nbytes - full * bs;
    const uint8_t *src = in;
    uint8_t *dst = out;
    uint8_t cc[CCMODE_MAX_BLOCK_SIZE], pp[CCMODE_MAX_BLOCK_SIZE];

    if (full == 0) return;

    if (r == 0) {
        xts->xts(ctx, tweak, full, src, dst);
        return;
    }

    if (full > 1) {
        xts->xts(ctx, tweak, full - 1, src, dst);
    }
    src += (full - 1) * bs;
    dst += (full - 1) * bs;

    // cc = enc(p_(m-1)) under t_(m-1), c_m takes its first r bytes
    xts->xts(ctx, tweak, 1, src, cc);
    cc_copy(r, pp, src + bs);
    cc_copy(bs - r, pp + r, cc + r);
    cc_copy(r, dst + bs, cc);

    // c_(m-1) = enc(p_m || cc tail) under t_m
    xts->xts(ctx, tweak, 1, pp, dst);

    cc_clear(bs, cc);
    cc_clear(bs, pp);
}

size_t ccpad_xts_decrypt(const struct ccmode_xts *xts, ccxts_ctx *ctx, ccxts_tweak *tweak, size_t nbytes, const void *in, void *out)
{
    size_t bs = xts->block_size;
    size_t full = nbytes / bs;
    size_t r = nbytes - full * bs;
    const uint8_t *src = in;
    uint8_t *dst = out;
    uint8_t cc[CCMODE_MAX_BLOCK_SIZE], pp[CCMODE_MAX_BLOCK_SIZE], scratch[CCMODE_MAX_BLOCK_SIZE] = { 0 };

    if (full == 0) return 0;

    if (r == 0) {
        xts->xts(ctx, tweak, full, src, dst);
        return nbytes;
    }

    if (full > 1) {
        xts->xts(ctx, tweak, full - 1, src, dst);
    }
    src += (full - 1) * bs;
    dst += (full - 1) * bs;

    // the stolen block needs t_m before t_(m-1), so step a copy of the tweak forward
    ccxts_tweak_decl(xts->tweak_size, later);
    cc_copy(xts->tweak_size, later, tweak);
    xts->xts(ctx, later, 1, scratch, scratch);

    xts->xts(ctx, later, 1, src, pp);
    cc_copy(r, cc, src + bs);
    cc_copy(bs - r, cc + r, pp + r);

    xts->xts(ctx, tweak, 1, cc, dst);
    cc_copy(r, dst + bs, pp);

    // leave the caller's tweak past both blocks
    cc_copy(xts->tweak_size, tweak, later);

    ccxts_tweak_clear(xts->tweak_size, later);
    cc_clear(bs, cc);
    cc_clear(bs, pp);
    cc_clear(bs, scratch);
    return nbytes;
}
