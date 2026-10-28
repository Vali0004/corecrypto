/*
 * Copyright (C) 2026, PureDarwin contributors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

// pd interim LLM-written code, experimental and not secure: unaudited, unfuzzed, no side-channel review
#include <corecrypto/cc_priv.h>
#include <corecrypto/ccdes.h>

// des cbc-mac over zero-padded input, the final block goes to out and its low word is returned (fips 113)
uint32_t ccdes_cbc_cksum(const void *in, void *out, size_t length, const void *key, size_t key_nbytes, const void *ivec)
{
    const struct ccmode_cbc *cbc = ccdes_cbc_encrypt_mode();
    const uint8_t *p = in;
    uint8_t iv[8], block[8];
    cccbc_ctx_decl(cbc->size, ctx);

    if (cbc->init(cbc, ctx, key_nbytes, key) != 0) return 0;
    cc_copy(8, iv, ivec);
    cc_clear(8, block);

    while (length) {
        size_t take = length < 8 ? length : 8;
        uint8_t m[8] = { 0 };
        cc_copy(take, m, p);
        cbc->cbc(ctx, (cccbc_iv *)iv, 1, m, block);
        p += take;
        length -= take;
    }

    if (out) cc_copy(8, out, block);
    uint32_t r = ((uint32_t)block[4] << 24) | ((uint32_t)block[5] << 16) | ((uint32_t)block[6] << 8) | block[7];
    cccbc_ctx_clear(cbc->size, ctx);
    return r;
}
