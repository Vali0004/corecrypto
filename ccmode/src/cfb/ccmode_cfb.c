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

// feedback modes keep the shift register, the keystream and its offset (sp 800-38a 6.3, 6.4)

size_t ccmode_stream_ctx_size(const struct ccmode_ecb *ecb)
{
    return ccn_sizeof_size(sizeof(struct _ccmode_stream_key)) +
           2 * ccn_sizeof_size(ecb->block_size) +
           ccn_sizeof_size(ecb->size);
}

cc_error_t ccmode_stream_init(const struct ccmode_ecb *ecb, void *ctx, size_t key_size, const void *key, const void *iv)
{
    struct _ccmode_stream_key *k = CCMODE_STREAM_KEY(ctx);

    k->ecb = ecb;
    k->offset = ecb->block_size;

    if (iv) {
        cc_copy(ecb->block_size, CCMODE_STREAM_KEY_REG(ctx), iv);
    } else {
        cc_clear(ecb->block_size, CCMODE_STREAM_KEY_REG(ctx));
    }
    cc_clear(ecb->block_size, CCMODE_STREAM_KEY_PAD(ctx));

    return ecb->init(ecb, CCMODE_STREAM_KEY_ECB_CTX(ctx), key_size, key);
}

static cc_error_t ccmode_cfb_init(const struct ccmode_cfb *cfb, cccfb_ctx *ctx, size_t key_size, const void *key, const void *iv)
{
    return ccmode_stream_init(cfb->custom, ctx, key_size, key, iv);
}

// full-block cfb: the register is the previous ciphertext block (sp 800-38a 6.3)
static cc_error_t ccmode_cfb_crypt(cccfb_ctx *ctx, size_t nbytes, const void *in, void *out, bool encrypt)
{
    struct _ccmode_stream_key *k = CCMODE_STREAM_KEY(ctx);
    const struct ccmode_ecb *ecb = k->ecb;
    size_t bs = ecb->block_size;
    uint8_t *reg = CCMODE_STREAM_KEY_REG(ctx);
    uint8_t *pad = CCMODE_STREAM_KEY_PAD(ctx);
    const uint8_t *src = in;
    uint8_t *dst = out;
    cc_error_t err;

    for (size_t i = 0; i < nbytes; i++) {
        if (k->offset == bs) {
            err = ecb->ecb(CCMODE_STREAM_KEY_ECB_CTX(ctx), 1, reg, pad);
            if (err) return err;
            k->offset = 0;
        }

        uint8_t c = src[i];
        uint8_t p = c ^ pad[k->offset];
        dst[i] = p;
        reg[k->offset++] = encrypt ? p : c;
    }

    return CCERR_OK;
}

static cc_error_t ccmode_cfb_encrypt(cccfb_ctx *ctx, size_t nbytes, const void *in, void *out)
{
    return ccmode_cfb_crypt(ctx, nbytes, in, out, true);
}

static cc_error_t ccmode_cfb_decrypt(cccfb_ctx *ctx, size_t nbytes, const void *in, void *out)
{
    return ccmode_cfb_crypt(ctx, nbytes, in, out, false);
}

void ccmode_factory_cfb_encrypt(struct ccmode_cfb *cfb, const struct ccmode_ecb *ecb)
{
    cfb->size = ccmode_stream_ctx_size(ecb);
    cfb->block_size = 1;
    cfb->init = &ccmode_cfb_init;
    cfb->cfb = &ccmode_cfb_encrypt;
    cfb->custom = ecb;
}

void ccmode_factory_cfb_decrypt(struct ccmode_cfb *cfb, const struct ccmode_ecb *ecb)
{
    cfb->size = ccmode_stream_ctx_size(ecb);
    cfb->block_size = 1;
    cfb->init = &ccmode_cfb_init;
    cfb->cfb = &ccmode_cfb_decrypt;
    cfb->custom = ecb;
}

static cc_error_t ccmode_cfb8_init(const struct ccmode_cfb8 *cfb8, cccfb8_ctx *ctx, size_t key_size, const void *key, const void *iv)
{
    return ccmode_stream_init(cfb8->custom, ctx, key_size, key, iv);
}

// 8-bit cfb: shift one ciphertext byte into the register per step (sp 800-38a 6.3, s = 8)
static cc_error_t ccmode_cfb8_crypt(cccfb8_ctx *ctx, size_t nbytes, const void *in, void *out, bool encrypt)
{
    struct _ccmode_stream_key *k = CCMODE_STREAM_KEY(ctx);
    const struct ccmode_ecb *ecb = k->ecb;
    size_t bs = ecb->block_size;
    uint8_t *reg = CCMODE_STREAM_KEY_REG(ctx);
    uint8_t *pad = CCMODE_STREAM_KEY_PAD(ctx);
    const uint8_t *src = in;
    uint8_t *dst = out;
    cc_error_t err;

    for (size_t i = 0; i < nbytes; i++) {
        err = ecb->ecb(CCMODE_STREAM_KEY_ECB_CTX(ctx), 1, reg, pad);
        if (err) return err;

        uint8_t c = src[i];
        uint8_t p = c ^ pad[0];
        dst[i] = p;

        memmove(reg, reg + 1, bs - 1);
        reg[bs - 1] = encrypt ? p : c;
    }

    return CCERR_OK;
}

static cc_error_t ccmode_cfb8_encrypt(cccfb8_ctx *ctx, size_t nbytes, const void *in, void *out)
{
    return ccmode_cfb8_crypt(ctx, nbytes, in, out, true);
}

static cc_error_t ccmode_cfb8_decrypt(cccfb8_ctx *ctx, size_t nbytes, const void *in, void *out)
{
    return ccmode_cfb8_crypt(ctx, nbytes, in, out, false);
}

void ccmode_factory_cfb8_encrypt(struct ccmode_cfb8 *cfb8, const struct ccmode_ecb *ecb)
{
    cfb8->size = ccmode_stream_ctx_size(ecb);
    cfb8->block_size = 1;
    cfb8->init = &ccmode_cfb8_init;
    cfb8->cfb8 = &ccmode_cfb8_encrypt;
    cfb8->custom = ecb;
}

void ccmode_factory_cfb8_decrypt(struct ccmode_cfb8 *cfb8, const struct ccmode_ecb *ecb)
{
    cfb8->size = ccmode_stream_ctx_size(ecb);
    cfb8->block_size = 1;
    cfb8->init = &ccmode_cfb8_init;
    cfb8->cfb8 = &ccmode_cfb8_decrypt;
    cfb8->custom = ecb;
}
