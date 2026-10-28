/*
 * Copyright (C) 2026, PureDarwin contributors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

// pd interim LLM-written code, experimental and not secure: unaudited, unfuzzed, no side-channel review
#include <corecrypto/cc_priv.h>
#include <corecrypto/ccansikdf.h>

// k_i = hash(z || counter_32 || sharedinfo), counter from 1 (sec 1 v2 3.6.1)
int ccansikdf_x963(const struct ccdigest_info *di,
                   const size_t Z_len, const unsigned char *Z,
                   const size_t sharedinfo_byte_len, const void *sharedinfo,
                   const size_t key_len, uint8_t *key)
{
    size_t hlen = di->output_size;
    uint8_t k[MAX_DIGEST_OUTPUT_SIZE];
    size_t left = key_len;
    ccdigest_di_decl(di, ctx);

    if (hlen > sizeof(k)) return CCERR_PARAMETER;
    if (key_len == 0 || (key_len + hlen - 1) / hlen > 0xffffffffULL) return CCERR_PARAMETER;

    for (uint32_t i = 1; left; i++) {
        uint8_t be[4] = { (uint8_t)(i >> 24), (uint8_t)(i >> 16), (uint8_t)(i >> 8), (uint8_t)i };

        ccdigest_init(di, ctx);
        ccdigest_update(di, ctx, Z_len, Z);
        ccdigest_update(di, ctx, 4, be);
        ccdigest_update(di, ctx, sharedinfo_byte_len, sharedinfo);
        ccdigest_final(di, ctx, k);

        size_t take = left < hlen ? left : hlen;
        cc_copy(take, key, k);
        key += take;
        left -= take;
    }

    ccdigest_di_clear(di, ctx);
    cc_clear(sizeof(k), k);
    return CCERR_OK;
}
