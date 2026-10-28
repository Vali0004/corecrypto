/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
// pd interim LLM-written code, experimental and not secure: unaudited, unfuzzed, no side-channel review

#include <corecrypto/cc_priv.h>
#include <corecrypto/ccchacha20poly1305_priv.h>

// aead_chacha20_poly1305 (rfc 8439 2.8)

static const struct ccchacha20poly1305_info ccchacha20poly1305_info_default;

const struct ccchacha20poly1305_info *ccchacha20poly1305_info(void)
{
    return &ccchacha20poly1305_info_default;
}

int ccchacha20poly1305_init(const struct ccchacha20poly1305_info *info, ccchacha20poly1305_ctx *ctx, const uint8_t *key)
{
    (void)info;
    cc_clear(sizeof(*ctx), ctx);
    ccchacha20_init(&ctx->chacha20_ctx, key);
    ctx->state = CCCHACHA20POLY1305_STATE_SETNONCE;
    return CCERR_OK;
}

int ccchacha20poly1305_reset(const struct ccchacha20poly1305_info *info, ccchacha20poly1305_ctx *ctx)
{
    (void)info;
    ccchacha20_reset(&ctx->chacha20_ctx);
    cc_clear(sizeof(ctx->poly1305_ctx), &ctx->poly1305_ctx);
    ctx->aad_nbytes = 0;
    ctx->text_nbytes = 0;
    ctx->state = CCCHACHA20POLY1305_STATE_SETNONCE;
    return CCERR_OK;
}

// the one-time poly1305 key is the first half of block 0 (rfc 8439 2.6)
int ccchacha20poly1305_setnonce(const struct ccchacha20poly1305_info *info, ccchacha20poly1305_ctx *ctx, const uint8_t *nonce)
{
    uint8_t block[CCCHACHA20_BLOCK_NBYTES] = { 0 };
    (void)info;

    if (ctx->state != CCCHACHA20POLY1305_STATE_SETNONCE) return CCMODE_INVALID_CALL_SEQUENCE;

    ccchacha20_setnonce(&ctx->chacha20_ctx, nonce);
    ccchacha20_setcounter(&ctx->chacha20_ctx, 0);
    ccchacha20_update(&ctx->chacha20_ctx, sizeof(block), block, block);
    ccpoly1305_init(&ctx->poly1305_ctx, block);
    cc_clear(sizeof(block), block);

    // the stream position is block 1 now
    ctx->aad_nbytes = 0;
    ctx->text_nbytes = 0;
    ctx->state = CCCHACHA20POLY1305_STATE_AAD;
    return CCERR_OK;
}

int ccchacha20poly1305_incnonce(const struct ccchacha20poly1305_info *info, ccchacha20poly1305_ctx *ctx, uint8_t *nonce)
{
    uint32_t *st = ctx->chacha20_ctx.state;

    // nonce words are state[13..15], the low 64 bits count up little-endian
    uint64_t ctr = (uint64_t)st[14] | ((uint64_t)st[15] << 32);
    ctr++;
    if (ctr == 0) return CCMODE_INVALID_CALL_SEQUENCE;

    uint8_t n[CCCHACHA20_NONCE_NBYTES];
    for (int i = 0; i < 4; i++) n[i] = (uint8_t)(st[13] >> (8 * i));
    for (int i = 0; i < 8; i++) n[4 + i] = (uint8_t)(ctr >> (8 * i));

    ccchacha20poly1305_reset(info, ctx);
    cc_copy(sizeof(n), nonce, n);
    return ccchacha20poly1305_setnonce(info, ctx, n);
}

int ccchacha20poly1305_aad(const struct ccchacha20poly1305_info *info, ccchacha20poly1305_ctx *ctx, size_t nbytes, const void *aad)
{
    (void)info;
    if (ctx->state != CCCHACHA20POLY1305_STATE_AAD) return CCMODE_INVALID_CALL_SEQUENCE;
    if (nbytes == 0) return CCERR_OK;

    ccpoly1305_update(&ctx->poly1305_ctx, nbytes, aad);
    ctx->aad_nbytes += nbytes;
    return CCERR_OK;
}

static void pad16(ccpoly1305_ctx *poly, uint64_t n)
{
    static const uint8_t zeros[16];
    if (n % 16) ccpoly1305_update(poly, 16 - (size_t)(n % 16), zeros);
}

static int crypt_common(ccchacha20poly1305_ctx *ctx, size_t nbytes, const void *in, void *out, int want)
{
    if (ctx->state == CCCHACHA20POLY1305_STATE_AAD) {
        pad16(&ctx->poly1305_ctx, ctx->aad_nbytes);
        ctx->state = (uint8_t)want;
    }
    if (ctx->state != want) return CCMODE_INVALID_CALL_SEQUENCE;
    if (nbytes > CCCHACHA20POLY1305_TEXT_MAX_NBYTES - ctx->text_nbytes) return CCMODE_INVALID_INPUT;
    if (nbytes == 0) return CCERR_OK;

    if (want == CCCHACHA20POLY1305_STATE_DECRYPT) {
        ccpoly1305_update(&ctx->poly1305_ctx, nbytes, in);
        ccchacha20_update(&ctx->chacha20_ctx, nbytes, in, out);
    } else {
        ccchacha20_update(&ctx->chacha20_ctx, nbytes, in, out);
        ccpoly1305_update(&ctx->poly1305_ctx, nbytes, out);
    }
    ctx->text_nbytes += nbytes;
    return CCERR_OK;
}

int ccchacha20poly1305_encrypt(const struct ccchacha20poly1305_info *info, ccchacha20poly1305_ctx *ctx, size_t nbytes, const void *ptext, void *ctext)
{
    (void)info;
    return crypt_common(ctx, nbytes, ptext, ctext, CCCHACHA20POLY1305_STATE_ENCRYPT);
}

int ccchacha20poly1305_decrypt(const struct ccchacha20poly1305_info *info, ccchacha20poly1305_ctx *ctx, size_t nbytes, const void *ctext, void *ptext)
{
    (void)info;
    return crypt_common(ctx, nbytes, ctext, ptext, CCCHACHA20POLY1305_STATE_DECRYPT);
}

// mac over aad || pad || text || pad || le64(aad len) || le64(text len) (rfc 8439 2.8)
static int compute_tag(ccchacha20poly1305_ctx *ctx, uint8_t tag[16])
{
    uint8_t lens[16];

    if (ctx->state == CCCHACHA20POLY1305_STATE_AAD) {
        pad16(&ctx->poly1305_ctx, ctx->aad_nbytes);
    } else if (ctx->state == CCCHACHA20POLY1305_STATE_ENCRYPT || ctx->state == CCCHACHA20POLY1305_STATE_DECRYPT) {
        // fine
    } else {
        return CCMODE_INVALID_CALL_SEQUENCE;
    }

    pad16(&ctx->poly1305_ctx, ctx->text_nbytes);
    for (int i = 0; i < 8; i++) {
        lens[i] = (uint8_t)(ctx->aad_nbytes >> (8 * i));
        lens[8 + i] = (uint8_t)(ctx->text_nbytes >> (8 * i));
    }
    ccpoly1305_update(&ctx->poly1305_ctx, sizeof(lens), lens);
    ccpoly1305_final(&ctx->poly1305_ctx, tag);
    ctx->state = CCCHACHA20POLY1305_STATE_FINAL;
    return CCERR_OK;
}

int ccchacha20poly1305_finalize(const struct ccchacha20poly1305_info *info, ccchacha20poly1305_ctx *ctx, uint8_t *tag)
{
    (void)info;
    if (ctx->state == CCCHACHA20POLY1305_STATE_DECRYPT) return CCMODE_INVALID_CALL_SEQUENCE;
    return compute_tag(ctx, tag);
}

int ccchacha20poly1305_verify(const struct ccchacha20poly1305_info *info, ccchacha20poly1305_ctx *ctx, const uint8_t *tag)
{
    uint8_t computed[16];
    (void)info;

    if (ctx->state == CCCHACHA20POLY1305_STATE_ENCRYPT) return CCMODE_INVALID_CALL_SEQUENCE;
    int rc = compute_tag(ctx, computed);
    if (rc == 0 && cc_cmp_safe(sizeof(computed), computed, tag)) rc = CCMODE_INTEGRITY_FAILURE;
    cc_clear(sizeof(computed), computed);
    return rc;
}

int ccchacha20poly1305_encrypt_oneshot(const struct ccchacha20poly1305_info *info, const uint8_t *key, const uint8_t *nonce,
                                       size_t aad_nbytes, const void *aad, size_t ptext_nbytes, const void *ptext, void *ctext, uint8_t *tag)
{
    ccchacha20poly1305_ctx ctx;
    int rc = ccchacha20poly1305_init(info, &ctx, key);
    if (rc == 0) rc = ccchacha20poly1305_setnonce(info, &ctx, nonce);
    if (rc == 0) rc = ccchacha20poly1305_aad(info, &ctx, aad_nbytes, aad);
    if (rc == 0) rc = ccchacha20poly1305_encrypt(info, &ctx, ptext_nbytes, ptext, ctext);
    if (rc == 0) rc = ccchacha20poly1305_finalize(info, &ctx, tag);
    cc_clear(sizeof(ctx), &ctx);
    return rc;
}

int ccchacha20poly1305_decrypt_oneshot(const struct ccchacha20poly1305_info *info, const uint8_t *key, const uint8_t *nonce,
                                       size_t aad_nbytes, const void *aad, size_t ctext_nbytes, const void *ctext, void *ptext, const uint8_t *tag)
{
    ccchacha20poly1305_ctx ctx;
    int rc = ccchacha20poly1305_init(info, &ctx, key);
    if (rc == 0) rc = ccchacha20poly1305_setnonce(info, &ctx, nonce);
    if (rc == 0) rc = ccchacha20poly1305_aad(info, &ctx, aad_nbytes, aad);
    if (rc == 0) rc = ccchacha20poly1305_decrypt(info, &ctx, ctext_nbytes, ctext, ptext);
    if (rc == 0) rc = ccchacha20poly1305_verify(info, &ctx, tag);
    if (rc) cc_clear(ctext_nbytes, ptext);
    cc_clear(sizeof(ctx), &ctx);
    return rc;
}
