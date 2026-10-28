/*
 * Copyright (C) 2026, PureDarwin contributors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

// pd interim LLM-written code, experimental and not secure: unaudited, unfuzzed, no side-channel review
#include <corecrypto/ccmode.h>

size_t ccxts_context_size(const struct ccmode_xts *xts)
{
    return xts->size;
}

size_t ccxts_block_size(const struct ccmode_xts *xts)
{
    return xts->block_size;
}

cc_error_t ccxts_init(const struct ccmode_xts *xts, ccxts_ctx *ctx, size_t key_nbytes, const void *data_key, const void *tweak_key)
{
    return xts->init(xts, ctx, key_nbytes, data_key, tweak_key);
}

cc_error_t ccxts_set_tweak(const struct ccmode_xts *xts, ccxts_ctx *ctx, ccxts_tweak *tweak, const void *iv)
{
    return xts->set_tweak(ctx, tweak, iv);
}

void *ccxts_update(const struct ccmode_xts *xts, ccxts_ctx *ctx, ccxts_tweak *tweak, size_t nblocks, const void *in, void *out)
{
    return xts->xts(ctx, tweak, nblocks, in, out);
}
