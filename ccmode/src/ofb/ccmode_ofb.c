/*
 * Copyright (C) 2026, PureDarwin contributors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
// pd interim LLM-written code, experimental and not secure: unaudited, unfuzzed, no side-channel review

#include <corecrypto/cc_priv.h>
#include <corecrypto/ccmode_internal.h>

static cc_error_t ccmode_ofb_init(const struct ccmode_ofb *ofb, ccofb_ctx *ctx, size_t key_size, const void *key, const void *iv)
{
    return ccmode_stream_init(ofb->custom, ctx, key_size, key, iv);
}

// the register is re-encrypted on its own, independent of the data (sp 800-38a 6.4)
static cc_error_t ccmode_ofb_crypt(ccofb_ctx *ctx, size_t nbytes, const void *in, void *out)
{
    struct _ccmode_stream_key *k = CCMODE_STREAM_KEY(ctx);
    const struct ccmode_ecb *ecb = k->ecb;
    size_t bs = ecb->block_size;
    uint8_t *reg = CCMODE_STREAM_KEY_REG(ctx);
    const uint8_t *src = in;
    uint8_t *dst = out;
    cc_error_t err;

    for (size_t i = 0; i < nbytes; i++) {
        if (k->offset == bs) {
            err = ecb->ecb(CCMODE_STREAM_KEY_ECB_CTX(ctx), 1, reg, reg);
            if (err) return err;
            k->offset = 0;
        }
        dst[i] = src[i] ^ reg[k->offset++];
    }

    return CCERR_OK;
}

void ccmode_factory_ofb_crypt(struct ccmode_ofb *ofb, const struct ccmode_ecb *ecb)
{
    ofb->size = ccmode_stream_ctx_size(ecb);
    ofb->block_size = 1;
    ofb->init = &ccmode_ofb_init;
    ofb->ofb = &ccmode_ofb_crypt;
    ofb->custom = ecb;
}
