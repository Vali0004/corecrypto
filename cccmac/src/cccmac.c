/*
 * Copyright (C) 2026, PureDarwin contributors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

// pd interim LLM-written code, experimental and not secure: unaudited, unfuzzed, no side-channel review
#include <corecrypto/cc_priv.h>
#include <corecrypto/cccmac.h>

// private layout inside the 40-byte header: pending block, its length, the cbc mode
struct cccmac_state {
    uint8_t pending[16];
    uint64_t pending_len;
    uint64_t total;
    const struct ccmode_cbc *cbc;
};

#define CMAC_STATE(ctx)     ((struct cccmac_state *)(void *)(ctx))
#define CMAC_IV(ctx)        ((cccbc_iv *)((uint8_t *)(ctx) + cccmac_hdr_size))
#define CMAC_CBC_CTX(ctx)   ((cccbc_ctx *)((uint8_t *)(ctx) + cccmac_hdr_size + CMAC_STATE(ctx)->cbc->block_size))

_Static_assert(sizeof(struct cccmac_state) == sizeof(struct cccmac_ctx), "cmac state must fit the header");

// doubling in gf(2^128) with r = 0x87 (sp 800-38b 6.1)
static void cmac_dbl(uint8_t out[16], const uint8_t in[16])
{
    uint8_t carry = in[0] >> 7;
    for (int i = 0; i < 15; i++) {
        out[i] = (uint8_t)((in[i] << 1) | (in[i + 1] >> 7));
    }
    out[15] = (uint8_t)((in[15] << 1) ^ (0x87 & (0 - carry)));
}

static void cmac_raw(cccmac_ctx_t ctx, const uint8_t in[16], uint8_t out[16])
{
    uint8_t zero[16] = { 0 };
    CMAC_STATE(ctx)->cbc->cbc(CMAC_CBC_CTX(ctx), (cccbc_iv *)zero, 1, in, out);
}

int cccmac_init(const struct ccmode_cbc *cbc, cccmac_ctx_t ctx, size_t key_length, const void *key)
{
    key_length = (uint32_t)key_length;
    if (cbc->block_size != CMAC_BLOCKSIZE) return CCERR_PARAMETER;

    cc_clear(cccmac_hdr_size + cbc->block_size, ctx);
    CMAC_STATE(ctx)->cbc = cbc;
    return cbc->init(cbc, CMAC_CBC_CTX(ctx), key_length, key);
}

// the last block is held back until final so it can take k1 or k2
int cccmac_update(cccmac_ctx_t ctx, size_t data_length, const void *data)
{
    struct cccmac_state *st = CMAC_STATE(ctx);
    const uint8_t *in = data;

    while (data_length) {
        if (st->pending_len == 16) {
            st->cbc->cbc(CMAC_CBC_CTX(ctx), CMAC_IV(ctx), 1, st->pending, st->pending);
            st->pending_len = 0;
        }

        // whole blocks with more data behind them go straight through
        if (st->pending_len == 0 && data_length > 16) {
            size_t nblocks = (data_length - 1) / 16;
            uint8_t tmp[16];
            for (size_t i = 0; i < nblocks; i++) {
                st->cbc->cbc(CMAC_CBC_CTX(ctx), CMAC_IV(ctx), 1, in, tmp);
                in += 16;
            }
            cc_clear(16, tmp);
            data_length -= nblocks * 16;
            st->total += nblocks * 16;
            continue;
        }

        size_t take = 16 - (size_t)st->pending_len;
        if (take > data_length) take = data_length;
        cc_copy(take, st->pending + st->pending_len, in);
        st->pending_len += take;
        st->total += take;
        in += take;
        data_length -= take;
    }
    return CCERR_OK;
}

// t = msb(e(k, m_n* xor c_(n-1))) with k1 for a whole last block and k2 after 10* padding (sp 800-38b 6.2)
int cccmac_final_generate(cccmac_ctx_t ctx, size_t mac_length, void *mac)
{
    struct cccmac_state *st = CMAC_STATE(ctx);
    uint8_t l[16] = { 0 }, k[16], last[16], tag[16];

    mac_length = (uint32_t)mac_length;
    if (mac_length == 0 || mac_length > 16) return CCERR_PARAMETER;

    cmac_raw(ctx, l, l);
    cmac_dbl(k, l);

    cc_clear(16, last);
    cc_copy((size_t)st->pending_len, last, st->pending);
    if (st->pending_len == 16) {
        cc_xor(16, last, last, k);
    } else {
        last[st->pending_len] = 0x80;
        cmac_dbl(l, k);
        cc_xor(16, last, last, l);
    }

    st->cbc->cbc(CMAC_CBC_CTX(ctx), CMAC_IV(ctx), 1, last, tag);
    cc_copy(mac_length, mac, tag);

    cc_clear(16, l);
    cc_clear(16, k);
    cc_clear(16, last);
    cc_clear(16, tag);
    return CCERR_OK;
}

int cccmac_final_verify(cccmac_ctx_t ctx, size_t expected_mac_length, const void *expected_mac)
{
    uint8_t tag[16];
    int rc = cccmac_final_generate(ctx, expected_mac_length, tag);
    if (rc == 0 && cc_cmp_safe((uint32_t)expected_mac_length, tag, expected_mac)) rc = CCERR_INTEGRITY;
    cc_clear(sizeof(tag), tag);
    return rc;
}

int cccmac_one_shot_generate(const struct ccmode_cbc *cbc, size_t key_length, const void *key,
                             size_t data_length, const void *data, size_t mac_length, void *mac)
{
    cccmac_mode_decl(cbc, ctx);
    int rc = cccmac_init(cbc, ctx, key_length, key);
    if (rc == 0) rc = cccmac_update(ctx, data_length, data);
    if (rc == 0) rc = cccmac_final_generate(ctx, mac_length, mac);
    cccmac_mode_clear(cbc, ctx);
    return rc;
}

int cccmac_one_shot_verify(const struct ccmode_cbc *cbc, size_t key_length, const void *key,
                           size_t data_length, const void *data, size_t expected_mac_length, const void *expected_mac)
{
    cccmac_mode_decl(cbc, ctx);
    int rc = cccmac_init(cbc, ctx, key_length, key);
    if (rc == 0) rc = cccmac_update(ctx, data_length, data);
    if (rc == 0) rc = cccmac_final_verify(ctx, expected_mac_length, expected_mac);
    cccmac_mode_clear(cbc, ctx);
    return rc;
}

const struct ccmode_cbc *cccmac_cbc(cccmac_ctx_t ctx)
{
    return CMAC_STATE(ctx)->cbc;
}
