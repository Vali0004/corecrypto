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
#include <corecrypto/ccmode_factory.h>

#define GCM_KEY(ctx) CCMODE_GCM_KEY(ctx)

static void gcm_inc32(uint8_t block[16])
{
    // only the low 32 bits count (sp 800-38d 6.2)
    for (int i = 15; i >= 12; i--) {
        if (++block[i] != 0) break;
    }
}

static cc_error_t gcm_encrypt_block(struct _ccmode_gcm_key *k, const uint8_t in[16], uint8_t out[16])
{
    return k->ecb->ecb(CCMODE_GCM_KEY_ECB_CTX(k), 1, in, out);
}

static cc_error_t ccmode_gcm_init(const struct ccmode_gcm *gcm, ccgcm_ctx *ctx, size_t key_size, const void *key)
{
    struct _ccmode_gcm_key *k = GCM_KEY(ctx);
    const struct ccmode_ecb *ecb = gcm->custom;
    cc_error_t err;

    if (ecb->block_size != 16) return CCERR_PARAMETER;

    cc_clear(sizeof(*k), k);
    k->ecb = ecb;
    k->encdec = gcm->encdec;

    err = ecb->init(ecb, CCMODE_GCM_KEY_ECB_CTX(k), key_size, key);
    if (err) return err;

    // hash subkey h = e(k, 0^128) (sp 800-38d 7.1 step 1)
    err = gcm_encrypt_block(k, k->H, k->H);
    if (err) return err;

    k->state = CCGCM_STATE_INIT;
    return CCERR_OK;
}

static void gcm_ghash_partial(struct _ccmode_gcm_key *k, size_t nbytes, const uint8_t *in)
{
    while (nbytes) {
        size_t take = 16 - k->buf_len;
        if (take > nbytes) take = nbytes;

        cc_copy(take, k->buf + k->buf_len, in);
        k->buf_len += (uint32_t)take;
        in += take;
        nbytes -= take;

        if (k->buf_len == 16) {
            ccmode_gcm_ghash(k, 16, k->buf);
            k->buf_len = 0;
        }
    }
}

static void gcm_ghash_flush(struct _ccmode_gcm_key *k)
{
    if (k->buf_len) {
        cc_clear(16 - k->buf_len, k->buf + k->buf_len);
        ccmode_gcm_ghash(k, 16, k->buf);
        k->buf_len = 0;
    }
}

static cc_error_t ccmode_gcm_set_iv_internal(ccgcm_ctx *ctx, size_t iv_size, const void *iv)
{
    struct _ccmode_gcm_key *k = GCM_KEY(ctx);

    if (k->state != CCGCM_STATE_INIT) return CCMODE_INVALID_CALL_SEQUENCE;

    if (iv_size == 12) {
        // j0 = iv || 0^31 || 1 (sp 800-38d 7.1 step 2)
        cc_copy(12, k->J0, iv);
        k->J0[12] = 0;
        k->J0[13] = 0;
        k->J0[14] = 0;
        k->J0[15] = 1;
    } else {
        // j0 = ghash(iv || 0^(s+64) || [len(iv)]64)
        uint8_t lenblock[16] = { 0 };
        uint64_t bits = (uint64_t)iv_size * 8;

        cc_clear(16, k->X);
        k->buf_len = 0;
        if (iv_size) gcm_ghash_partial(k, iv_size, iv);
        gcm_ghash_flush(k);

        for (int i = 0; i < 8; i++) {
            lenblock[15 - i] = (uint8_t)(bits >> (8 * i));
        }
        ccmode_gcm_ghash(k, 16, lenblock);
        cc_copy(16, k->J0, k->X);
        cc_clear(16, k->X);
    }

    cc_copy(16, k->Y, k->J0);
    gcm_inc32(k->Y);
    k->buf_len = 0;
    k->aad_len = 0;
    k->text_len = 0;
    k->state = CCGCM_STATE_IV;
    return CCERR_OK;
}

static cc_error_t ccmode_gcm_set_iv(ccgcm_ctx *ctx, size_t iv_size, const void *iv)
{
    if (GCM_KEY(ctx)->flags & CCGCM_FLAGS_INIT_WITH_IV) return CCMODE_INVALID_CALL_SEQUENCE;
    if (iv_size == 0) return CCMODE_INVALID_INPUT;
    return ccmode_gcm_set_iv_internal(ctx, iv_size, iv);
}

static cc_error_t ccmode_gcm_aad(ccgcm_ctx *ctx, size_t nbytes, const void *in)
{
    struct _ccmode_gcm_key *k = GCM_KEY(ctx);

    if (k->state == CCGCM_STATE_IV) {
        k->state = CCGCM_STATE_AAD;
    }
    if (k->state != CCGCM_STATE_AAD) return CCMODE_INVALID_CALL_SEQUENCE;
    if (nbytes == 0) return CCERR_OK;

    k->aad_len += nbytes;
    gcm_ghash_partial(k, nbytes, in);
    return CCERR_OK;
}

// gctr with inc32 counters, ghash taken over the ciphertext (sp 800-38d 6.5, 7.1, 7.2)
static cc_error_t ccmode_gcm_crypt(ccgcm_ctx *ctx, size_t nbytes, const void *in, void *out)
{
    struct _ccmode_gcm_key *k = GCM_KEY(ctx);
    const uint8_t *src = in;
    uint8_t *dst = out;
    bool encrypt = (k->encdec == CCMODE_GCM_ENCRYPTOR);
    cc_error_t err;

    if (k->state == CCGCM_STATE_IV || k->state == CCGCM_STATE_AAD) {
        gcm_ghash_flush(k);
        k->state = CCGCM_STATE_TEXT;
        k->buf_len = 0;
    }
    if (k->state != CCGCM_STATE_TEXT) return CCMODE_INVALID_CALL_SEQUENCE;

    // the plaintext limit is 2^39 - 256 bits
    if (k->text_len + nbytes < k->text_len || k->text_len + nbytes > ((1ULL << 36) - 32)) {
        return CCMODE_INVALID_INPUT;
    }
    k->text_len += nbytes;

    for (size_t i = 0; i < nbytes; i++) {
        if (k->buf_len == 0) {
            err = gcm_encrypt_block(k, k->Y, k->pad);
            if (err) return err;
            gcm_inc32(k->Y);
        }

        uint8_t c_in = src[i];
        uint8_t c_out = c_in ^ k->pad[k->buf_len];
        dst[i] = c_out;
        k->buf[k->buf_len++] = encrypt ? c_out : c_in;

        if (k->buf_len == 16) {
            ccmode_gcm_ghash(k, 16, k->buf);
            k->buf_len = 0;
        }
    }

    return CCERR_OK;
}

static cc_error_t ccmode_gcm_finalize(ccgcm_ctx *ctx, size_t tag_size, void *tag)
{
    struct _ccmode_gcm_key *k = GCM_KEY(ctx);
    uint8_t lenblock[16];
    uint8_t full_tag[16];
    cc_error_t err;

    if (tag_size == 0 || tag_size > 16) return CCMODE_INVALID_INPUT;

    if (k->state == CCGCM_STATE_IV || k->state == CCGCM_STATE_AAD || k->state == CCGCM_STATE_TEXT) {
        gcm_ghash_flush(k);
    } else {
        return CCMODE_INVALID_CALL_SEQUENCE;
    }

    // s = ghash(a || c || [len(a)]64 || [len(c)]64), t = msb(gctr(j0, s)) (sp 800-38d 7.1 steps 5-6)
    uint64_t abits = k->aad_len * 8, cbits = k->text_len * 8;
    for (int i = 0; i < 8; i++) {
        lenblock[7 - i] = (uint8_t)(abits >> (8 * i));
        lenblock[15 - i] = (uint8_t)(cbits >> (8 * i));
    }
    ccmode_gcm_ghash(k, 16, lenblock);

    err = gcm_encrypt_block(k, k->J0, full_tag);
    if (err) return err;
    cc_xor(16, full_tag, full_tag, k->X);

    k->state = CCGCM_STATE_FINAL;

    if (k->encdec == CCMODE_GCM_ENCRYPTOR) {
        cc_copy(tag_size, tag, full_tag);
        cc_clear(16, full_tag);
        return CCERR_OK;
    }

    // decrypt compares, then also hands back the computed tag for legacy callers
    int diff = cc_cmp_safe(tag_size, tag, full_tag);
    cc_copy(tag_size, tag, full_tag);
    cc_clear(16, full_tag);
    return diff ? CCMODE_INTEGRITY_FAILURE : CCERR_OK;
}

static cc_error_t ccmode_gcm_reset(ccgcm_ctx *ctx)
{
    struct _ccmode_gcm_key *k = GCM_KEY(ctx);

    cc_clear(16, k->X);
    cc_clear(16, k->buf);
    cc_clear(16, k->pad);
    k->buf_len = 0;
    k->aad_len = 0;
    k->text_len = 0;

    if (k->flags & CCGCM_FLAGS_INIT_WITH_IV) {
        // keep j0, the caller moves it on with ccgcm_inc_iv
        cc_copy(16, k->Y, k->J0);
        gcm_inc32(k->Y);
        k->state = CCGCM_STATE_IV;
    } else {
        k->state = CCGCM_STATE_INIT;
    }
    return CCERR_OK;
}

static void gcm_factory(struct ccmode_gcm *gcm, const struct ccmode_ecb *ecb, int encdec)
{
    gcm->size = ccn_sizeof_size(sizeof(struct _ccmode_gcm_key)) + ccn_sizeof_size(ecb->size);
    gcm->encdec = encdec;
    gcm->block_size = 1;
    gcm->init = &ccmode_gcm_init;
    gcm->set_iv = &ccmode_gcm_set_iv;
    gcm->gmac = &ccmode_gcm_aad;
    gcm->gcm = &ccmode_gcm_crypt;
    gcm->finalize = &ccmode_gcm_finalize;
    gcm->reset = &ccmode_gcm_reset;
    gcm->custom = ecb;
}

void ccmode_factory_gcm_encrypt(struct ccmode_gcm *gcm, const struct ccmode_ecb *ecb_encrypt)
{
    gcm_factory(gcm, ecb_encrypt, CCMODE_GCM_ENCRYPTOR);
}

void ccmode_factory_gcm_decrypt(struct ccmode_gcm *gcm, const struct ccmode_ecb *ecb_encrypt)
{
    gcm_factory(gcm, ecb_encrypt, CCMODE_GCM_DECRYPTOR);
}

int ccgcm_set_iv_legacy(const struct ccmode_gcm *mode, ccgcm_ctx *ctx, size_t iv_nbytes, const void *iv)
{
    // only the factory mode is known here, so zero-length ivs go through the internal path
    if (mode->set_iv != &ccmode_gcm_set_iv) {
        return mode->set_iv(ctx, iv_nbytes, iv);
    }
    if (GCM_KEY(ctx)->flags & CCGCM_FLAGS_INIT_WITH_IV) return CCMODE_INVALID_CALL_SEQUENCE;
    return ccmode_gcm_set_iv_internal(ctx, iv_nbytes, iv);
}

int ccgcm_init_with_iv(const struct ccmode_gcm *mode, ccgcm_ctx *ctx, size_t key_nbytes, const void *key, const void *iv)
{
    int rc = mode->init(mode, ctx, key_nbytes, key);
    if (rc) return rc;

    rc = ccmode_gcm_set_iv_internal(ctx, 12, iv);
    if (rc) return rc;

    GCM_KEY(ctx)->flags |= CCGCM_FLAGS_INIT_WITH_IV;
    return CCERR_OK;
}

int ccgcm_inc_iv(const struct ccmode_gcm *mode, ccgcm_ctx *ctx, void *iv)
{
    struct _ccmode_gcm_key *k = GCM_KEY(ctx);
    (void)mode;

    if (!(k->flags & CCGCM_FLAGS_INIT_WITH_IV)) return CCMODE_INVALID_CALL_SEQUENCE;
    if (k->state != CCGCM_STATE_IV) return CCMODE_INVALID_CALL_SEQUENCE;

    // 4-byte salt then a big-endian 8-byte counter
    for (int i = 11; i >= 4; i--) {
        if (++k->J0[i] != 0) break;
    }
    // a counter that wrapped to zero would repeat an iv
    bool zero = true;
    for (int i = 4; i < 12; i++) {
        if (k->J0[i]) zero = false;
    }
    if (zero) return CCMODE_INVALID_CALL_SEQUENCE;

    cc_copy(12, iv, k->J0);
    cc_copy(16, k->Y, k->J0);
    gcm_inc32(k->Y);
    return CCERR_OK;
}

int ccgcm_one_shot(const struct ccmode_gcm *mode,
                   size_t key_nbytes, const void *key,
                   size_t iv_nbytes, const void *iv,
                   size_t adata_nbytes, const void *adata,
                   size_t nbytes, const void *in, void *out,
                   size_t tag_nbytes, void *tag)
{
    int rc;
    ccgcm_ctx_decl(mode->size, ctx);

    rc = mode->init(mode, ctx, key_nbytes, key);
    if (rc == 0) rc = mode->set_iv(ctx, iv_nbytes, iv);
    if (rc == 0) rc = mode->gmac(ctx, adata_nbytes, adata);
    if (rc == 0) rc = mode->gcm(ctx, nbytes, in, out);
    if (rc == 0) rc = mode->finalize(ctx, tag_nbytes, tag);

    ccgcm_ctx_clear(mode->size, ctx);
    return rc;
}

int ccgcm_one_shot_legacy(const struct ccmode_gcm *mode,
                          size_t key_nbytes, const void *key,
                          size_t iv_nbytes, const void *iv,
                          size_t adata_nbytes, const void *adata,
                          size_t nbytes, const void *in, void *out,
                          size_t tag_nbytes, void *tag)
{
    int rc;
    ccgcm_ctx_decl(mode->size, ctx);

    rc = mode->init(mode, ctx, key_nbytes, key);
    if (rc == 0) rc = ccgcm_set_iv_legacy(mode, ctx, iv_nbytes, iv);
    if (rc == 0) rc = mode->gmac(ctx, adata_nbytes, adata);
    if (rc == 0) rc = mode->gcm(ctx, nbytes, in, out);
    if (rc == 0) rc = mode->finalize(ctx, tag_nbytes, tag);

    ccgcm_ctx_clear(mode->size, ctx);
    return rc;
}
