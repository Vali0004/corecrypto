/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
// pd interim LLM-written code, experimental and not secure: unaudited, unfuzzed, no side-channel review

#include <corecrypto/ccdigest_internal.h>
#include <corecrypto/ccdigest_priv.h>

// merkle-damgard padding: 0x80, zeros, then the bit length (fips 180-4 5.1, rfc 1320/1321 3.1-3.2)
void ccdigest_final_64be_pad(const struct ccdigest_info *di, ccdigest_ctx_t ctx, size_t len_size, bool big_endian)
{
    size_t bs = di->block_size;
    uint8_t *data = ccdigest_data(di, ctx);
    size_t num = ccdigest_num(di, ctx);
    uint64_t nbits = ccdigest_nbits(di, ctx) + ((uint64_t)num << 3);

    data[num++] = 0x80;
    if (num > bs - len_size) {
        while (num < bs) data[num++] = 0;
        di->compress(ccdigest_state(di, ctx), 1, data);
        num = 0;
    }
    while (num < bs - 8) data[num++] = 0;

    for (int i = 0; i < 8; i++) {
        data[big_endian ? (bs - 1 - i) : (bs - 8 + i)] = (uint8_t)(nbits >> (8 * i));
    }
    di->compress(ccdigest_state(di, ctx), 1, data);
    ccdigest_num(di, ctx) = 0;
}

void ccdigest_final_64be(const struct ccdigest_info *di, ccdigest_ctx_t ctx, void *digest)
{
    uint8_t *out = (uint8_t *)digest;
    const uint32_t *st = ccdigest_state_u32(di, ctx);

    ccdigest_final_64be_pad(di, ctx, 8, true);
    for (size_t i = 0; i < di->output_size; i++) {
        out[i] = (uint8_t)(st[i / 4] >> (24 - 8 * (i % 4)));
    }
}
