/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
// pd interim LLM-written code, experimental and not secure: unaudited, unfuzzed, no side-channel review

#include <corecrypto/ccdigest_internal.h>

void ccdigest_final_64be_pad(const struct ccdigest_info *di, ccdigest_ctx_t ctx, size_t len_size, bool big_endian);

void ccdigest_final_64le(const struct ccdigest_info *di, ccdigest_ctx_t ctx, void *digest)
{
    uint8_t *out = (uint8_t *)digest;
    const uint32_t *st = ccdigest_state_u32(di, ctx);

    ccdigest_final_64be_pad(di, ctx, 8, false);
    for (size_t i = 0; i < di->output_size; i++) {
        out[i] = (uint8_t)(st[i / 4] >> (8 * (i % 4)));
    }
}
