/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
// pd interim LLM-written code, experimental and not secure: unaudited, unfuzzed, no side-channel review

#include <corecrypto/ccdigest_priv.h>

void ccdigest_update(const struct ccdigest_info *di, ccdigest_ctx_t ctx, size_t length, const void *data)
{
    const uint8_t *ptr = (const uint8_t *)data;
    size_t bs = di->block_size;

    while (length) {
        size_t num = ccdigest_num(di, ctx);

        if (num == 0 && length >= bs) {
            // whole blocks straight from the caller's buffer
            size_t blocks = length / bs;
            size_t bytes = blocks * bs;

            di->compress(ccdigest_state(di, ctx), blocks, ptr);
            ccdigest_nbits(di, ctx) += ((uint64_t)bytes << 3);
            length -= bytes;
            ptr += bytes;
            continue;
        }

        size_t take = bs - num;
        if (take > length) take = length;

        cc_copy(take, ccdigest_data(di, ctx) + num, ptr);
        num += take;
        length -= take;
        ptr += take;

        if (num == bs) {
            di->compress(ccdigest_state(di, ctx), 1, ccdigest_data(di, ctx));
            ccdigest_nbits(di, ctx) += ((uint64_t)bs << 3);
            num = 0;
        }
        ccdigest_num(di, ctx) = (uint32_t)num;
    }
}
