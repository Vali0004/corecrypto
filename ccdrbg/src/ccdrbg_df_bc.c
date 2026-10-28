/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
// pd interim LLM-written code, experimental and not secure: unaudited, unfuzzed, no side-channel review

#include "corecrypto/cc.h"
#include "corecrypto/ccmode.h"
#include <corecrypto/cc_priv.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/ccdrbg_df.h>
#include <corecrypto/ccmode_internal.h>
#include <corecrypto/ccn.h>

#define MAX_DF_TEMP_SIZE    (CCAES_KEY_SIZE_256 + CCAES_BLOCK_SIZE)
#define MAX_DF_BLOCK_SIZE   (CCAES_BLOCK_SIZE)

// bcc state: the chaining value lives in the iv, partial input waits in buf
struct bcc_state {
    const ccdrbg_df_bc_ctx_t *df;
    cccbc_iv *iv;
    uint8_t buf[MAX_DF_BLOCK_SIZE];
    uint8_t out[MAX_DF_BLOCK_SIZE];
    size_t used;
};

static cc_error_t bcc_absorb(struct bcc_state *st, const void *in, size_t nbytes)
{
    size_t bs = cccbc_block_size(st->df->cbc);
    const uint8_t *p = in;
    cc_error_t err;

    while (nbytes) {
        size_t take = bs - st->used;
        if (take > nbytes) take = nbytes;
        cc_copy(take, st->buf + st->used, p);
        st->used += take;
        p += take;
        nbytes -= take;

        if (st->used == bs) {
            err = cccbc_update(st->df->cbc, st->df->cbc_ctx, st->iv, 1, st->buf, st->out);
            if (err) return err;
            st->used = 0;
        }
    }
    return CCERR_OK;
}

// block_cipher_df: bcc over iv || l || n || input || 0x80 || 0*, then expand under the new key (sp 800-90a 10.3.2, 10.3.3)
cc_error_t ccdrbg_df_bc_derive_keys(const ccdrbg_df_ctx_t *ctx,
                                 size_t nvec,
                                 const cc_iovec_t *iovecs,
                                 size_t key_nbytes,
                                 void *keys)
{
    const ccdrbg_df_bc_ctx_t *df_ctx = (const ccdrbg_df_bc_ctx_t *)ctx;
    size_t bs = cccbc_block_size(df_ctx->cbc);
    size_t total = 0;
    uint8_t temp[MAX_DF_TEMP_SIZE];
    size_t temp_need = df_ctx->key_nbytes + bs;
    uint8_t *kp = keys;
    cc_error_t err = CCERR_OK;
    cccbc_ctx_decl(cccbc_context_size(df_ctx->cbc), cbc_ctx);
    cccbc_iv_decl(bs, cbc_iv);

    if (bs != MAX_DF_BLOCK_SIZE || temp_need > sizeof(temp)) return CCERR_PARAMETER;

    for (size_t v = 0; v < nvec; v++) {
        total += iovecs[v].nbytes;
    }

    uint8_t ln[8];
    cc_store32_be((uint32_t)total, ln);
    cc_store32_be((uint32_t)key_nbytes, ln + 4);
    size_t pad = bs - ((8 + total + 1) % bs);
    if (pad == bs) pad = 0;
    static const uint8_t tail[1 + MAX_DF_BLOCK_SIZE] = { 0x80 };

    for (uint32_t i = 0; i * bs < temp_need; i++) {
        struct bcc_state st = { .df = df_ctx, .iv = cbc_iv, .used = 0 };
        uint8_t ivblk[MAX_DF_BLOCK_SIZE] = { 0 };
        cc_store32_be(i, ivblk);

        cccbc_iv_clear(bs, cbc_iv);
        err = bcc_absorb(&st, ivblk, bs);
        if (err == 0) err = bcc_absorb(&st, ln, sizeof(ln));
        for (size_t j = 0; err == 0 && j < nvec; j++) {
            err = bcc_absorb(&st, iovecs[j].base, iovecs[j].nbytes);
        }
        if (err == 0) err = bcc_absorb(&st, tail, 1 + pad);
        if (err) goto out;

        size_t take = temp_need - i * bs < bs ? temp_need - i * bs : bs;
        cc_copy(take, temp + i * bs, st.out);
        cc_clear(sizeof(st.buf), st.buf);
        cc_clear(sizeof(st.out), st.out);
    }

    // k = leftmost keylen of temp, x = the next block, then x = e(k, x) repeatedly
    err = cccbc_init(df_ctx->cbc, cbc_ctx, df_ctx->key_nbytes, temp);
    if (err) goto out;

    uint8_t x[MAX_DF_BLOCK_SIZE];
    cc_copy(bs, x, temp + df_ctx->key_nbytes);
    while (key_nbytes > 0) {
        cccbc_iv_clear(bs, cbc_iv);
        err = cccbc_update(df_ctx->cbc, cbc_ctx, cbc_iv, 1, x, x);
        if (err) break;
        size_t take = key_nbytes < bs ? key_nbytes : bs;
        cc_copy(take, kp, x);
        kp += take;
        key_nbytes -= take;
    }
    cc_clear(sizeof(x), x);

out:
    cc_clear(sizeof(temp), temp);
    cccbc_ctx_clear(cccbc_context_size(df_ctx->cbc), cbc_ctx);
    cccbc_iv_clear(bs, cbc_iv);
    return err;
}

cc_error_t ccdrbg_df_bc_init(ccdrbg_df_bc_ctx_t *ctx, const struct ccmode_cbc *cbc, size_t key_nbytes)
{
    cc_error_t err = CCERR_INTERNAL;

    static const uint8_t df_key[CCAES_KEY_SIZE_256] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };

    err = cccbc_init(cbc, ctx->cbc_ctx, key_nbytes, df_key);
    if (err != CCERR_OK) {
        return err;
    }

    ctx->cbc = cbc;
    ctx->derive_keys = &ccdrbg_df_bc_derive_keys;
    ctx->key_nbytes = key_nbytes;

    return CCERR_OK;
}
