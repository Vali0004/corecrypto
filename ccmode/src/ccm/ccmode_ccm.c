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

#define CCM_MODE_INIT   0
#define CCM_MODE_IV     1
#define CCM_MODE_AD     2
#define CCM_MODE_DATA   3
#define CCM_MODE_DONE   4

#define NONCE(n) ((struct _ccmode_ccm_nonce *)(n))

static cc_error_t ccm_block(ccccm_ctx *ctx, const uint8_t in[16], uint8_t out[16])
{
    const struct ccmode_ecb *ecb = CCMODE_CCM_KEY(ctx)->ecb;
    return ecb->ecb(CCMODE_CCM_KEY_ECB_CTX(ctx), 1, in, out);
}

static cc_error_t ccmode_ccm_init(const struct ccmode_ccm *ccm, ccccm_ctx *ctx, size_t key_size, const void *key)
{
    const struct ccmode_ecb *ecb = ccm->custom;

    if (ecb->block_size != 16) return CCERR_PARAMETER;
    CCMODE_CCM_KEY(ctx)->ecb = ecb;
    return ecb->init(ecb, CCMODE_CCM_KEY_ECB_CTX(ctx), key_size, key);
}

// absorb bytes into the cbc-mac chain y_i = e(b_i xor y_(i-1)) (sp 800-38c 6.1 step 4)
static cc_error_t ccm_mac_absorb(ccccm_ctx *ctx, struct _ccmode_ccm_nonce *n, size_t nbytes, const uint8_t *in)
{
    cc_error_t err;

    while (nbytes) {
        size_t take = 16 - n->b_i_len;
        if (take > nbytes) take = nbytes;

        cc_xor(take, n->B_i + n->b_i_len, n->B_i + n->b_i_len, in);
        n->b_i_len += (uint32_t)take;
        in += take;
        nbytes -= take;

        if (n->b_i_len == 16) {
            err = ccm_block(ctx, n->B_i, n->B_i);
            if (err) return err;
            n->b_i_len = 0;
        }
    }
    return CCERR_OK;
}

static cc_error_t ccm_mac_flush(ccccm_ctx *ctx, struct _ccmode_ccm_nonce *n)
{
    cc_error_t err = CCERR_OK;

    // zero padding leaves the remaining bytes of b_i as they are under xor
    if (n->b_i_len) {
        err = ccm_block(ctx, n->B_i, n->B_i);
        n->b_i_len = 0;
    }
    return err;
}

static cc_error_t ccmode_ccm_set_iv(ccccm_ctx *ctx, ccccm_nonce *nonce_ctx, size_t nonce_len, const void *nonce,
                                    size_t mac_size, size_t auth_len, size_t data_len)
{
    struct _ccmode_ccm_nonce *n = NONCE(nonce_ctx);
    uint8_t b0[16];
    cc_error_t err;

    // n in 7..13, t in {4,6,...,16}, q = 15 - n (sp 800-38c a.1)
    if (nonce_len < 7 || nonce_len > 13) return CCMODE_INVALID_INPUT;
    if (mac_size < 4 || mac_size > 16 || (mac_size & 1)) return CCMODE_INVALID_INPUT;

    size_t q = 15 - nonce_len;
    if (q < 8 && (uint64_t)data_len >> (8 * q)) return CCMODE_INVALID_INPUT;

    cc_clear(sizeof(*n), n);
    n->nonce_size = nonce_len;
    n->mac_size = mac_size;

    // b0 = flags || n || q (sp 800-38c a.2.1)
    b0[0] = (uint8_t)(((auth_len > 0) << 6) | (((mac_size - 2) / 2) << 3) | (q - 1));
    cc_copy(nonce_len, b0 + 1, nonce);
    uint64_t len = data_len;
    for (size_t i = 0; i < q; i++) {
        b0[15 - i] = (uint8_t)len;
        len = (i < 7) ? (len >> 8) : 0;
    }
    err = ccm_block(ctx, b0, n->B_i);
    if (err) return err;

    // ctr_i = flags' || n || [i]q, s0 masks the tag (sp 800-38c a.3)
    n->A_i[0] = (uint8_t)(q - 1);
    cc_copy(nonce_len, n->A_i + 1, nonce);
    cc_clear(q, n->A_i + 1 + nonce_len);
    err = ccm_block(ctx, n->A_i, n->MAC);
    if (err) return err;
    n->A_i[15] = 1;

    // associated data length prefix (sp 800-38c a.2.2)
    if (auth_len > 0) {
        uint8_t enc[10];
        size_t enc_len;
        uint64_t a = auth_len;

        if (a < 0xff00) {
            enc[0] = (uint8_t)(a >> 8);
            enc[1] = (uint8_t)a;
            enc_len = 2;
        } else if (a <= 0xffffffffULL) {
            enc[0] = 0xff;
            enc[1] = 0xfe;
            for (int i = 0; i < 4; i++) enc[2 + i] = (uint8_t)(a >> (24 - 8 * i));
            enc_len = 6;
        } else {
            enc[0] = 0xff;
            enc[1] = 0xff;
            for (int i = 0; i < 8; i++) enc[2 + i] = (uint8_t)(a >> (56 - 8 * i));
            enc_len = 10;
        }
        err = ccm_mac_absorb(ctx, n, enc_len, enc);
        if (err) return err;
        n->mode = CCM_MODE_AD;
    } else {
        n->mode = CCM_MODE_DATA;
    }

    n->buflen = 0;
    return CCERR_OK;
}

static cc_error_t ccmode_ccm_cbcmac(ccccm_ctx *ctx, ccccm_nonce *nonce_ctx, size_t nbytes, const void *in)
{
    struct _ccmode_ccm_nonce *n = NONCE(nonce_ctx);

    if (nbytes == 0) return CCERR_OK;
    if (n->mode != CCM_MODE_AD) return CCMODE_INVALID_CALL_SEQUENCE;
    return ccm_mac_absorb(ctx, n, nbytes, in);
}

static cc_error_t ccm_enter_data(ccccm_ctx *ctx, struct _ccmode_ccm_nonce *n)
{
    cc_error_t err;

    if (n->mode == CCM_MODE_AD) {
        err = ccm_mac_flush(ctx, n);
        if (err) return err;
        n->mode = CCM_MODE_DATA;
    }
    return (n->mode == CCM_MODE_DATA) ? CCERR_OK : CCMODE_INVALID_CALL_SEQUENCE;
}

static void ccm_inc_counter(struct _ccmode_ccm_nonce *n)
{
    size_t q = (size_t)(n->A_i[0] & 7) + 1;
    for (size_t i = 0; i < q; i++) {
        if (++n->A_i[15 - i] != 0) break;
    }
}

static cc_error_t ccm_crypt(ccccm_ctx *ctx, ccccm_nonce *nonce_ctx, size_t nbytes, const void *in, void *out, bool encrypt)
{
    struct _ccmode_ccm_nonce *n = NONCE(nonce_ctx);
    const uint8_t *src = in;
    uint8_t *dst = out;
    cc_error_t err;

    err = ccm_enter_data(ctx, n);
    if (err) return err;

    for (size_t i = 0; i < nbytes; i++) {
        if (n->buflen == 0) {
            err = ccm_block(ctx, n->A_i, n->buf);
            if (err) return err;
            ccm_inc_counter(n);
        }

        uint8_t x = src[i];
        uint8_t y = x ^ n->buf[n->buflen];
        n->buflen = (n->buflen + 1) & 15;
        dst[i] = y;

        uint8_t p = encrypt ? x : y;
        err = ccm_mac_absorb(ctx, n, 1, &p);
        if (err) return err;
    }
    return CCERR_OK;
}

static cc_error_t ccmode_ccm_encrypt(ccccm_ctx *ctx, ccccm_nonce *nonce_ctx, size_t nbytes, const void *in, void *out)
{
    return ccm_crypt(ctx, nonce_ctx, nbytes, in, out, true);
}

static cc_error_t ccmode_ccm_decrypt(ccccm_ctx *ctx, ccccm_nonce *nonce_ctx, size_t nbytes, const void *in, void *out)
{
    return ccm_crypt(ctx, nonce_ctx, nbytes, in, out, false);
}

// t = msb_tlen(y_r) xor msb_tlen(s0) (sp 800-38c 6.1 steps 5-8)
static cc_error_t ccmode_ccm_finalize(ccccm_ctx *ctx, ccccm_nonce *nonce_ctx, void *mac)
{
    struct _ccmode_ccm_nonce *n = NONCE(nonce_ctx);
    cc_error_t err;

    err = ccm_enter_data(ctx, n);
    if (err) return err;
    err = ccm_mac_flush(ctx, n);
    if (err) return err;

    cc_xor(n->mac_size, mac, n->B_i, n->MAC);
    n->mode = CCM_MODE_DONE;
    return CCERR_OK;
}

static cc_error_t ccmode_ccm_reset(ccccm_ctx *ctx, ccccm_nonce *nonce_ctx)
{
    (void)ctx;
    cc_clear(sizeof(struct _ccmode_ccm_nonce), nonce_ctx);
    return CCERR_OK;
}

static void ccm_factory(struct ccmode_ccm *ccm, const struct ccmode_ecb *ecb, bool encrypt)
{
    ccm->size = ccn_sizeof_size(sizeof(struct _ccmode_ccm_key)) + ccn_sizeof_size(ecb->size);
    ccm->nonce_size = ccn_sizeof_size(sizeof(struct _ccmode_ccm_nonce));
    ccm->block_size = 1;
    ccm->init = &ccmode_ccm_init;
    ccm->set_iv = &ccmode_ccm_set_iv;
    ccm->cbcmac = &ccmode_ccm_cbcmac;
    ccm->ccm = encrypt ? &ccmode_ccm_encrypt : &ccmode_ccm_decrypt;
    ccm->finalize = &ccmode_ccm_finalize;
    ccm->reset = &ccmode_ccm_reset;
    ccm->custom = ecb;
    ccm->enc_mode = encrypt;
}

void ccmode_factory_ccm_encrypt(struct ccmode_ccm *ccm, const struct ccmode_ecb *ecb_encrypt)
{
    ccm_factory(ccm, ecb_encrypt, true);
}

void ccmode_factory_ccm_decrypt(struct ccmode_ccm *ccm, const struct ccmode_ecb *ecb_encrypt)
{
    ccm_factory(ccm, ecb_encrypt, false);
}

int ccccm_one_shot(const struct ccmode_ccm *mode,
                   size_t key_len, const void *key,
                   size_t nonce_len, const void *nonce,
                   size_t nbytes, const void *in, void *out,
                   size_t adata_len, const void *adata,
                   size_t mac_size, void *mac)
{
    int rc;
    uint8_t computed[16];
    ccccm_ctx_decl(mode->size, ctx);
    ccccm_nonce_decl(mode->nonce_size, nonce_ctx);

    rc = mode->init(mode, ctx, key_len, key);
    if (rc == 0) rc = mode->set_iv(ctx, nonce_ctx, nonce_len, nonce, mac_size, adata_len, nbytes);
    if (rc == 0) rc = mode->cbcmac(ctx, nonce_ctx, adata_len, adata);
    if (rc == 0) rc = mode->ccm(ctx, nonce_ctx, nbytes, in, out);
    if (rc == 0) rc = mode->finalize(ctx, nonce_ctx, computed);

    if (rc == 0) {
        if (mode->enc_mode) {
            cc_copy(mac_size, mac, computed);
        } else if (cc_cmp_safe(mac_size, mac, computed)) {
            cc_clear(nbytes, out);
            rc = CCMODE_INTEGRITY_FAILURE;
        }
    }

    cc_clear(sizeof(computed), computed);
    ccccm_ctx_clear(mode->size, ctx);
    ccccm_nonce_clear(mode->nonce_size, nonce_ctx);
    return rc;
}
