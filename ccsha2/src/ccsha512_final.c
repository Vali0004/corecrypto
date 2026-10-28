/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
// pd interim LLM-written code, experimental and not secure: unaudited, unfuzzed, no side-channel review

#include "ccsha2_internal.h"
#include <corecrypto/ccdigest_priv.h>

void ccdigest_final_64be_pad(const struct ccdigest_info *di, ccdigest_ctx_t ctx, size_t len_size, bool big_endian);

// sha-384 and sha-512 use a 128-bit length field and 64-bit words (fips 180-4 5.1.2)
void ccsha512_final(const struct ccdigest_info *di, ccdigest_ctx_t ctx, void *digest)
{
    uint8_t *out = (uint8_t *)digest;
    const uint64_t *st = ccdigest_state_u64(di, ctx);

    ccdigest_final_64be_pad(di, ctx, 16, true);
    for (size_t i = 0; i < di->output_size; i++) {
        out[i] = (uint8_t)(st[i / 8] >> (56 - 8 * (i % 8)));
    }
}

void ccsha512_224_final(const struct ccdigest_info *di, ccdigest_ctx_t ctx, void *digest)
{
    ccsha512_final(di, ctx, digest);
}
