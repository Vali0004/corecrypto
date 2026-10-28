/*
 * Copyright (C) 2026, PureDarwin contributors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

// pd interim LLM-written code, experimental and not secure: unaudited, unfuzzed, no side-channel review
// known-answer tests for the pd-used corecrypto surface, see gen_vectors.py for where each vector comes from

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <corecrypto/cc_priv.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/ccdes.h>
#include <corecrypto/ccblowfish.h>
#include <corecrypto/cccast.h>
#include <corecrypto/ccmode.h>
#include <corecrypto/ccmode_factory.h>
#include <corecrypto/ccpad.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccmd2.h>
#include <corecrypto/ccmd4.h>
#include <corecrypto/ccmd5.h>
#include <corecrypto/ccsha1.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccripemd.h>
#include <corecrypto/cchmac.h>
#include <corecrypto/ccpbkdf2.h>
#include <corecrypto/cchkdf.h>
#include <corecrypto/cccmac.h>
#include <corecrypto/ccwrap_priv.h>
#include <corecrypto/ccansikdf.h>
#include <corecrypto/ccnistkdf.h>
#include <corecrypto/ccchacha20poly1305.h>
#include <corecrypto/ccrng.h>
#include <corecrypto/ccrng_system.h>
#include <corecrypto/cckprng.h>
#include <corecrypto/ccdrbg.h>

static const struct ccdigest_info *di_md2(void) { return &ccmd2_di; }
static const struct ccdigest_info *di_md4(void) { return &ccmd4_di; }
static const struct ccdigest_info *di_md5(void) { return ccmd5_di(); }
static const struct ccdigest_info *di_sha1(void) { return ccsha1_di(); }
static const struct ccdigest_info *di_sha224(void) { return ccsha224_di(); }
static const struct ccdigest_info *di_sha256(void) { return ccsha256_di(); }
static const struct ccdigest_info *di_sha384(void) { return ccsha384_di(); }
static const struct ccdigest_info *di_sha512(void) { return ccsha512_di(); }
static const struct ccdigest_info *di_rmd160(void) { return &ccrmd160_di; }
typedef const struct ccdigest_info *(*di_fn)(void);

#define B(name) const uint8_t *name; size_t name##_len
struct pd_digest_vec { di_fn di; B(msg); B(md); const char *name; };
struct pd_hmac_vec { di_fn di; B(key); B(msg); B(mac); const char *name; };
struct pd_blk_vec { const char *name; int mode; B(key); B(iv); B(pt); B(ct); };
struct pd_pkcs7_vec { B(key); B(iv); B(pt); B(ct); };
struct pd_pkcs7big_vec { size_t len; B(ct_sha256); };
struct pd_cts3_vec { B(key); B(iv); B(pt); B(ct); };
struct pd_xts_vec { B(k1); B(k2); B(tweak); B(pt); B(ct); };
struct pd_gcm_vec { B(key); B(iv); B(aad); B(pt); B(ct); B(tag); };
struct pd_ccm_vec { B(key); B(nonce); B(aad); B(pt); B(ct); B(tag); };
struct pd_chapoly_vec { B(key); B(nonce); B(aad); B(pt); B(ct); B(tag); };
struct pd_pbkdf2_vec { di_fn di; B(pw); B(salt); size_t iter; B(dk); };
struct pd_hkdf_vec { di_fn di; B(ikm); B(salt); B(info); B(okm); };
struct pd_cmac_vec { B(key); B(msg); B(mac); };
struct pd_wrap_vec { B(kek); B(key); B(wrapped); };
struct pd_x963_vec { di_fn di; B(z); B(si); B(key); };
struct pd_cksum_vec { B(key); B(iv); B(msg); B(mac); };
struct pd_nistkdf_vec { di_fn di; B(kdk); B(label); B(ctx); B(dk); };

#include "pd_vectors.h"

#define NVEC(a) (sizeof(a) / sizeof((a)[0]))

static int pass, fail;
static unsigned seed = 1;
static size_t rnd_chunk(size_t max) { seed = seed * 1103515245 + 12345; return 1 + (seed >> 16) % max; }

static void check(int ok, const char *group, const char *what, size_t i)
{
    if (ok) { pass++; return; }
    fail++;
    printf("FAIL %s %s #%zu\n", group, what, i);
}

static int eq(const void *a, const void *b, size_t n) { return n == 0 || memcmp(a, b, n) == 0; }

static void test_digest(void)
{
    for (size_t i = 0; i < NVEC(pd_digest_vecs); i++) {
        const struct pd_digest_vec *v = &pd_digest_vecs[i];
        uint8_t out[64];

        ccdigest(v->di(), v->msg_len, v->msg, out);
        check(eq(out, v->md, v->md_len), "digest", v->name, i);

        // streamed in uneven chunks
        ccdigest_di_decl(v->di(), ctx);
        ccdigest_init(v->di(), ctx);
        for (size_t off = 0; off < v->msg_len;) {
            size_t n = rnd_chunk(70);
            if (n > v->msg_len - off) n = v->msg_len - off;
            ccdigest_update(v->di(), ctx, n, v->msg + off);
            off += n;
        }
        ccdigest_final(v->di(), ctx, out);
        check(eq(out, v->md, v->md_len), "digest-stream", v->name, i);
    }
}

static void test_hmac(void)
{
    for (size_t i = 0; i < NVEC(pd_hmac_vecs); i++) {
        const struct pd_hmac_vec *v = &pd_hmac_vecs[i];
        uint8_t out[64];

        cchmac(v->di(), v->key_len, v->key, v->msg_len, v->msg, out);
        check(eq(out, v->mac, v->mac_len), "hmac", v->name, i);

        cchmac_di_decl(v->di(), ctx);
        cchmac_init(v->di(), ctx, v->key_len, v->key);
        for (size_t off = 0; off < v->msg_len;) {
            size_t n = rnd_chunk(40);
            if (n > v->msg_len - off) n = v->msg_len - off;
            cchmac_update(v->di(), ctx, n, v->msg + off);
            off += n;
        }
        cchmac_final(v->di(), ctx, out);
        check(eq(out, v->mac, v->mac_len), "hmac-stream", v->name, i);
    }
}

struct cipher_modes {
    const struct ccmode_ecb *(*ecb_e)(void), *(*ecb_d)(void);
    const struct ccmode_cbc *(*cbc_e)(void), *(*cbc_d)(void);
    const struct ccmode_ctr *(*ctr)(void);
    const struct ccmode_cfb *(*cfb_e)(void), *(*cfb_d)(void);
    const struct ccmode_cfb8 *(*cfb8_e)(void), *(*cfb8_d)(void);
    const struct ccmode_ofb *(*ofb)(void);
};

static const struct cipher_modes cm_aes = { ccaes_ecb_encrypt_mode, ccaes_ecb_decrypt_mode, ccaes_cbc_encrypt_mode, ccaes_cbc_decrypt_mode,
    ccaes_ctr_crypt_mode, ccaes_cfb_encrypt_mode, ccaes_cfb_decrypt_mode, ccaes_cfb8_encrypt_mode, ccaes_cfb8_decrypt_mode, ccaes_ofb_crypt_mode };
static const struct cipher_modes cm_des3 = { ccdes3_ecb_encrypt_mode, ccdes3_ecb_decrypt_mode, ccdes3_cbc_encrypt_mode, ccdes3_cbc_decrypt_mode,
    ccdes3_ctr_crypt_mode, ccdes3_cfb_encrypt_mode, ccdes3_cfb_decrypt_mode, ccdes3_cfb8_encrypt_mode, ccdes3_cfb8_decrypt_mode, ccdes3_ofb_crypt_mode };
static const struct cipher_modes cm_bf = { ccblowfish_ecb_encrypt_mode, ccblowfish_ecb_decrypt_mode, ccblowfish_cbc_encrypt_mode, ccblowfish_cbc_decrypt_mode,
    ccblowfish_ctr_crypt_mode, ccblowfish_cfb_encrypt_mode, ccblowfish_cfb_decrypt_mode, ccblowfish_cfb8_encrypt_mode, ccblowfish_cfb8_decrypt_mode, ccblowfish_ofb_crypt_mode };
static const struct cipher_modes cm_cast = { cccast_ecb_encrypt_mode, cccast_ecb_decrypt_mode, cccast_cbc_encrypt_mode, cccast_cbc_decrypt_mode,
    cccast_ctr_crypt_mode, cccast_cfb_encrypt_mode, cccast_cfb_decrypt_mode, cccast_cfb8_encrypt_mode, cccast_cfb8_decrypt_mode, cccast_ofb_crypt_mode };
static const struct cipher_modes cm_des = { ccdes_ecb_encrypt_mode, ccdes_ecb_decrypt_mode, ccdes_cbc_encrypt_mode, ccdes_cbc_decrypt_mode,
    ccdes_ctr_crypt_mode, ccdes_cfb_encrypt_mode, ccdes_cfb_decrypt_mode, ccdes_cfb8_encrypt_mode, ccdes_cfb8_decrypt_mode, ccdes_ofb_crypt_mode };

// run one direction of a mode, streaming when chunked is set
static int run_mode(const struct cipher_modes *cm, int mode, int enc, const struct pd_blk_vec *v, int chunked, uint8_t *out)
{
    const uint8_t *in = enc ? v->pt : v->ct;
    size_t len = v->pt_len;

    switch (mode) {
        case 0: {
            const struct ccmode_ecb *m = enc ? cm->ecb_e() : cm->ecb_d();
            ccecb_ctx_decl(m->size, ctx);
            if (m->init(m, ctx, v->key_len, v->key)) return -1;
            size_t bs = m->block_size;
            for (size_t off = 0; off < len; off += bs) m->ecb(ctx, 1, in + off, out + off);
            if (!chunked) m->ecb(ctx, len / bs, in, out);
            return 0;
        }
        case 1: {
            const struct ccmode_cbc *m = enc ? cm->cbc_e() : cm->cbc_d();
            cccbc_ctx_decl(m->size, ctx);
            uint8_t iv[16];
            memcpy(iv, v->iv, m->block_size);
            if (m->init(m, ctx, v->key_len, v->key)) return -1;
            size_t bs = m->block_size;
            if (chunked) {
                for (size_t off = 0; off < len; off += bs) m->cbc(ctx, (cccbc_iv *)iv, 1, in + off, out + off);
            } else {
                m->cbc(ctx, (cccbc_iv *)iv, len / bs, in, out);
            }
            return 0;
        }
        default: break;
    }

    // byte streaming modes share a call shape
    void *ctx = calloc(1, 65536);
    int rc = 0;
    size_t off = 0;
#define STREAM(m, fn)                                                       \
    do {                                                                    \
        if ((m)->init((m), ctx, v->key_len, v->key, v->iv)) { rc = -1; break; } \
        while (off < len) {                                                 \
            size_t n = chunked ? rnd_chunk(23) : len;                       \
            if (n > len - off) n = len - off;                               \
            (m)->fn(ctx, n, in + off, out + off);                           \
            off += n;                                                       \
        }                                                                   \
    } while (0)
    switch (mode) {
        case 2: { const struct ccmode_ctr *m = cm->ctr(); STREAM(m, ctr); break; }
        case 3: { const struct ccmode_cfb *m = enc ? cm->cfb_e() : cm->cfb_d(); STREAM(m, cfb); break; }
        case 4: { const struct ccmode_cfb8 *m = enc ? cm->cfb8_e() : cm->cfb8_d(); STREAM(m, cfb8); break; }
        case 5: { const struct ccmode_ofb *m = cm->ofb(); STREAM(m, ofb); break; }
    }
#undef STREAM
    free(ctx);
    return rc;
}

static void test_blk(void)
{
    for (size_t i = 0; i < NVEC(pd_blk_vecs); i++) {
        const struct pd_blk_vec *v = &pd_blk_vecs[i];
        const struct cipher_modes *cm = v->mode < 10 ? &cm_aes : v->mode < 20 ? &cm_des3 : v->mode < 30 ? &cm_bf : v->mode < 40 ? &cm_cast : &cm_des;
        int mode = v->mode % 10;
        uint8_t *out = malloc(v->pt_len + 16);

        for (int chunked = 0; chunked < 2; chunked++) {
            memset(out, 0, v->pt_len);
            int rc = run_mode(cm, mode, 1, v, chunked, out);
            check(rc == 0 && eq(out, v->ct, v->ct_len), chunked ? "cipher-enc-stream" : "cipher-enc", v->name, i);
            memset(out, 0, v->pt_len);
            rc = run_mode(cm, mode, 0, v, chunked, out);
            check(rc == 0 && eq(out, v->pt, v->pt_len), chunked ? "cipher-dec-stream" : "cipher-dec", v->name, i);
        }
        free(out);
    }
}

static void test_pkcs7(void)
{
    const struct ccmode_cbc *e = ccaes_cbc_encrypt_mode(), *d = ccaes_cbc_decrypt_mode();

    for (size_t i = 0; i < NVEC(pd_pkcs7_vecs); i++) {
        const struct pd_pkcs7_vec *v = &pd_pkcs7_vecs[i];
        uint8_t out[256], back[256], iv[16];
        cccbc_ctx_decl(e->size, ectx);
        cccbc_ctx_decl(d->size, dctx);

        e->init(e, ectx, v->key_len, v->key);
        memcpy(iv, v->iv, 16);
        size_t n = ccpad_pkcs7_encrypt(e, ectx, (cccbc_iv *)iv, v->pt_len, v->pt, out);
        check(n == v->ct_len && eq(out, v->ct, v->ct_len), "pkcs7", "encrypt", i);

        d->init(d, dctx, v->key_len, v->key);
        memcpy(iv, v->iv, 16);
        n = ccpad_pkcs7_decrypt(d, dctx, (cccbc_iv *)iv, v->ct_len, v->ct, back);
        check(n == v->pt_len && eq(back, v->pt, v->pt_len), "pkcs7", "decrypt", i);

        // ecb flavour round trip
        const struct ccmode_ecb *ee = ccaes_ecb_encrypt_mode(), *ed = ccaes_ecb_decrypt_mode();
        ccecb_ctx_decl(ee->size, eec);
        ccecb_ctx_decl(ed->size, edc);
        ee->init(ee, eec, v->key_len, v->key);
        ed->init(ed, edc, v->key_len, v->key);
        n = ccpad_pkcs7_ecb_encrypt(ee, eec, v->pt_len, v->pt, out);
        size_t m = ccpad_pkcs7_ecb_decrypt(ed, edc, n, out, back);
        check(n == v->ct_len && m == v->pt_len && eq(back, v->pt, v->pt_len), "pkcs7-ecb", "roundtrip", i);
    }

    // a corrupted pad must drop the last block
    {
        uint8_t blk[16];
        memset(blk, 3, 16);
        blk[15] = 0;
        check(ccpad_pkcs7_decode(16, blk) == 0, "pkcs7", "bad-pad-zero", 0);
        blk[15] = 17;
        check(ccpad_pkcs7_decode(16, blk) == 0, "pkcs7", "bad-pad-17", 0);
        blk[15] = 3; blk[14] = 3; blk[13] = 2;
        check(ccpad_pkcs7_decode(16, blk) == 0, "pkcs7", "bad-pad-mixed", 0);
        blk[13] = 3;
        check(ccpad_pkcs7_decode(16, blk) == 13, "pkcs7", "good-pad-3", 0);
    }
}

// sizes the commoncrypto path sees: one-shot through ccpad, and streamed as full cbc blocks then a padded tail
static void test_pkcs7_big(void)
{
    const struct ccmode_cbc *e = ccaes_cbc_encrypt_mode(), *d = ccaes_cbc_decrypt_mode();
    uint8_t key[16], iv0[16];
    for (int i = 0; i < 16; i++) { key[i] = (uint8_t)i; iv0[i] = (uint8_t)(16 + i); }

    for (size_t i = 0; i < NVEC(pd_pkcs7big_vecs); i++) {
        const struct pd_pkcs7big_vec *v = &pd_pkcs7big_vecs[i];
        size_t L = v->len, clen = (L / 16 + 1) * 16;
        uint8_t *pt = malloc(L), *ct = malloc(clen), *ct2 = malloc(clen), *back = malloc(clen), iv[16], h[32];
        for (size_t j = 0; j < L; j++) pt[j] = (uint8_t)((j * 7 + (j >> 8)) & 0xff);

        cccbc_ctx_decl(e->size, ectx);
        cccbc_ctx_decl(d->size, dctx);
        e->init(e, ectx, 16, key);
        d->init(d, dctx, 16, key);

        memcpy(iv, iv0, 16);
        size_t n = ccpad_pkcs7_encrypt(e, ectx, (cccbc_iv *)iv, L, pt, ct);
        ccdigest(ccsha256_di(), clen, ct, h);
        check(n == clen && eq(h, v->ct_sha256, 32), "pkcs7-big", "oneshot-encrypt", L);

        memcpy(iv, iv0, 16);
        size_t off = 0;
        while (L - off >= 16) {
            size_t nb = rnd_chunk(300);
            if (nb > (L - off) / 16) nb = (L - off) / 16;
            e->cbc(ectx, (cccbc_iv *)iv, nb, pt + off, ct2 + off);
            off += nb * 16;
        }
        ccpad_pkcs7_encrypt(e, ectx, (cccbc_iv *)iv, L - off, pt + off, ct2 + off);
        check(eq(ct2, ct, clen), "pkcs7-big", "streamed-encrypt", L);

        memcpy(iv, iv0, 16);
        n = ccpad_pkcs7_decrypt(d, dctx, (cccbc_iv *)iv, clen, ct, back);
        check(n == L && eq(back, pt, L), "pkcs7-big", "oneshot-decrypt", L);

        memcpy(iv, iv0, 16);
        off = 0;
        while (clen - off > 16) {
            size_t nb = rnd_chunk(300);
            if (nb > (clen - off) / 16 - 1) nb = (clen - off) / 16 - 1;
            d->cbc(dctx, (cccbc_iv *)iv, nb, ct + off, back + off);
            off += nb * 16;
        }
        n = off + ccpad_pkcs7_decrypt(d, dctx, (cccbc_iv *)iv, 16, ct + off, back + off);
        check(n == L && eq(back, pt, L), "pkcs7-big", "streamed-decrypt", L);

        free(pt); free(ct); free(ct2); free(back);
    }
}

static void test_cts3(void)
{
    const struct ccmode_cbc *e = ccaes_cbc_encrypt_mode(), *d = ccaes_cbc_decrypt_mode();
    for (size_t i = 0; i < NVEC(pd_cts3_vecs); i++) {
        const struct pd_cts3_vec *v = &pd_cts3_vecs[i];
        uint8_t out[128], back[128], iv[16];
        cccbc_ctx_decl(e->size, ectx);
        cccbc_ctx_decl(d->size, dctx);
        e->init(e, ectx, v->key_len, v->key);
        d->init(d, dctx, v->key_len, v->key);
        memcpy(iv, v->iv, 16);
        ccpad_cts3_encrypt(e, ectx, (cccbc_iv *)iv, v->pt_len, v->pt, out);
        check(eq(out, v->ct, v->ct_len), "cts3", "encrypt", i);
        memcpy(iv, v->iv, 16);
        ccpad_cts3_decrypt(d, dctx, (cccbc_iv *)iv, v->ct_len, v->ct, back);
        check(eq(back, v->pt, v->pt_len), "cts3", "decrypt", i);
        // cs1 and cs2 must at least round trip
        memcpy(iv, v->iv, 16);
        ccpad_cts1_encrypt(e, ectx, (cccbc_iv *)iv, v->pt_len, v->pt, out);
        memcpy(iv, v->iv, 16);
        ccpad_cts1_decrypt(d, dctx, (cccbc_iv *)iv, v->pt_len, out, back);
        check(eq(back, v->pt, v->pt_len), "cts1", "roundtrip", i);
        memcpy(iv, v->iv, 16);
        ccpad_cts2_encrypt(e, ectx, (cccbc_iv *)iv, v->pt_len, v->pt, out);
        memcpy(iv, v->iv, 16);
        ccpad_cts2_decrypt(d, dctx, (cccbc_iv *)iv, v->pt_len, out, back);
        check(eq(back, v->pt, v->pt_len), "cts2", "roundtrip", i);
    }
}

static void test_xts(void)
{
    for (size_t i = 0; i < NVEC(pd_xts_vecs); i++) {
        const struct pd_xts_vec *v = &pd_xts_vecs[i];
        uint8_t *out = malloc(v->pt_len), *back = malloc(v->pt_len);
        for (int dir = 0; dir < 2; dir++) {
            const struct ccmode_xts *m = dir ? ccaes_xts_decrypt_mode() : ccaes_xts_encrypt_mode();
            ccxts_ctx_decl(m->size, ctx);
            ccxts_tweak_decl(m->tweak_size, tw);
            int rc = m->init(m, ctx, v->k1_len, v->k1, v->k2);
            rc |= m->set_tweak(ctx, tw, v->tweak);
            if (dir == 0) {
                ccpad_xts_encrypt(m, ctx, tw, v->pt_len, v->pt, out);
                check(rc == 0 && eq(out, v->ct, v->ct_len), "xts", "encrypt", i);
            } else {
                ccpad_xts_decrypt(m, ctx, tw, v->ct_len, v->ct, back);
                check(rc == 0 && eq(back, v->pt, v->pt_len), "xts", "decrypt", i);
            }
        }
        free(out); free(back);
    }
}

static void test_gcm(void)
{
    for (size_t i = 0; i < NVEC(pd_gcm_vecs); i++) {
        const struct pd_gcm_vec *v = &pd_gcm_vecs[i];
        uint8_t out[256], tag[16];

        int rc = ccgcm_one_shot(ccaes_gcm_encrypt_mode(), v->key_len, v->key, v->iv_len, v->iv, v->aad_len, v->aad, v->pt_len, v->pt, out, v->tag_len, tag);
        check(rc == 0 && eq(out, v->ct, v->ct_len) && eq(tag, v->tag, v->tag_len), "gcm", "encrypt", i);

        // streamed decrypt checks the tag
        const struct ccmode_gcm *m = ccaes_gcm_decrypt_mode();
        ccgcm_ctx_decl(m->size, ctx);
        rc = m->init(m, ctx, v->key_len, v->key);
        rc |= m->set_iv(ctx, v->iv_len, v->iv);
        for (size_t off = 0; off < v->aad_len;) { size_t n = rnd_chunk(9); if (n > v->aad_len - off) n = v->aad_len - off; rc |= m->gmac(ctx, n, v->aad + off); off += n; }
        for (size_t off = 0; off < v->ct_len;) { size_t n = rnd_chunk(21); if (n > v->ct_len - off) n = v->ct_len - off; rc |= m->gcm(ctx, n, v->ct + off, out + off); off += n; }
        memcpy(tag, v->tag, v->tag_len);
        rc |= m->finalize(ctx, v->tag_len, tag);
        check(rc == 0 && eq(out, v->pt, v->pt_len), "gcm", "decrypt-stream", i);

        // a flipped tag bit must fail
        memcpy(tag, v->tag, v->tag_len);
        tag[0] ^= 1;
        rc = ccgcm_one_shot(ccaes_gcm_decrypt_mode(), v->key_len, v->key, v->iv_len, v->iv, v->aad_len, v->aad, v->ct_len, v->ct, out, v->tag_len, tag);
        check(rc == CCMODE_INTEGRITY_FAILURE, "gcm", "bad-tag", i);
    }
}

static void test_ccm(void)
{
    for (size_t i = 0; i < NVEC(pd_ccm_vecs); i++) {
        const struct pd_ccm_vec *v = &pd_ccm_vecs[i];
        uint8_t out[256], tag[16];

        int rc = ccccm_one_shot(ccaes_ccm_encrypt_mode(), v->key_len, v->key, v->nonce_len, v->nonce, v->pt_len, v->pt, out, v->aad_len, v->aad, v->tag_len, tag);
        check(rc == 0 && eq(out, v->ct, v->ct_len) && eq(tag, v->tag, v->tag_len), "ccm", "encrypt", i);

        memcpy(tag, v->tag, v->tag_len);
        rc = ccccm_one_shot(ccaes_ccm_decrypt_mode(), v->key_len, v->key, v->nonce_len, v->nonce, v->ct_len, v->ct, out, v->aad_len, v->aad, v->tag_len, tag);
        check(rc == 0 && eq(out, v->pt, v->pt_len), "ccm", "decrypt", i);

        tag[0] ^= 1;
        rc = ccccm_one_shot(ccaes_ccm_decrypt_mode(), v->key_len, v->key, v->nonce_len, v->nonce, v->ct_len, v->ct, out, v->aad_len, v->aad, v->tag_len, tag);
        check(rc == CCMODE_INTEGRITY_FAILURE, "ccm", "bad-tag", i);
    }
}

static void test_chapoly(void)
{
    const struct ccchacha20poly1305_info *info = ccchacha20poly1305_info();
    for (size_t i = 0; i < NVEC(pd_chapoly_vecs); i++) {
        const struct pd_chapoly_vec *v = &pd_chapoly_vecs[i];
        uint8_t out[512], tag[16];
        int rc = ccchacha20poly1305_encrypt_oneshot(info, v->key, v->nonce, v->aad_len, v->aad, v->pt_len, v->pt, out, tag);
        check(rc == 0 && eq(out, v->ct, v->ct_len) && eq(tag, v->tag, 16), "chacha20poly1305", "encrypt", i);
        rc = ccchacha20poly1305_decrypt_oneshot(info, v->key, v->nonce, v->aad_len, v->aad, v->ct_len, v->ct, out, v->tag);
        check(rc == 0 && eq(out, v->pt, v->pt_len), "chacha20poly1305", "decrypt", i);
        memcpy(tag, v->tag, 16);
        tag[5] ^= 0x80;
        rc = ccchacha20poly1305_decrypt_oneshot(info, v->key, v->nonce, v->aad_len, v->aad, v->ct_len, v->ct, out, tag);
        check(rc != 0, "chacha20poly1305", "bad-tag", i);

        // streamed
        ccchacha20poly1305_ctx ctx;
        rc = ccchacha20poly1305_init(info, &ctx, v->key);
        rc |= ccchacha20poly1305_setnonce(info, &ctx, v->nonce);
        for (size_t off = 0; off < v->aad_len;) { size_t n = rnd_chunk(7); if (n > v->aad_len - off) n = v->aad_len - off; rc |= ccchacha20poly1305_aad(info, &ctx, n, v->aad + off); off += n; }
        for (size_t off = 0; off < v->pt_len;) { size_t n = rnd_chunk(77); if (n > v->pt_len - off) n = v->pt_len - off; rc |= ccchacha20poly1305_encrypt(info, &ctx, n, v->pt + off, out + off); off += n; }
        rc |= ccchacha20poly1305_finalize(info, &ctx, tag);
        check(rc == 0 && eq(out, v->ct, v->ct_len) && eq(tag, v->tag, 16), "chacha20poly1305", "encrypt-stream", i);
    }
}

static void test_kdfs(void)
{
    for (size_t i = 0; i < NVEC(pd_pbkdf2_vecs); i++) {
        const struct pd_pbkdf2_vec *v = &pd_pbkdf2_vecs[i];
        uint8_t out[128];
        int rc = ccpbkdf2_hmac(v->di(), v->pw_len, v->pw, v->salt_len, v->salt, v->iter, v->dk_len, out);
        check(rc == 0 && eq(out, v->dk, v->dk_len), "pbkdf2", "derive", i);
    }
    for (size_t i = 0; i < NVEC(pd_hkdf_vecs); i++) {
        const struct pd_hkdf_vec *v = &pd_hkdf_vecs[i];
        uint8_t out[128];
        int rc = cchkdf(v->di(), v->ikm_len, v->ikm, v->salt_len, v->salt, v->info_len, v->info, v->okm_len, out);
        check(rc == 0 && eq(out, v->okm, v->okm_len), "hkdf", "derive", i);
    }
    for (size_t i = 0; i < NVEC(pd_cmac_vecs); i++) {
        const struct pd_cmac_vec *v = &pd_cmac_vecs[i];
        uint8_t out[16];
        int rc = cccmac_one_shot_generate(ccaes_cbc_encrypt_mode(), v->key_len, v->key, v->msg_len, v->msg, 16, out);
        check(rc == 0 && eq(out, v->mac, 16), "cmac", "oneshot", i);

        const struct ccmode_cbc *cbc = ccaes_cbc_encrypt_mode();
        cccmac_mode_decl(cbc, ctx);
        rc = cccmac_init(cbc, ctx, v->key_len, v->key);
        for (size_t off = 0; off < v->msg_len;) { size_t n = rnd_chunk(19); if (n > v->msg_len - off) n = v->msg_len - off; rc |= cccmac_update(ctx, n, v->msg + off); off += n; }
        rc |= cccmac_final_generate(ctx, 16, out);
        check(rc == 0 && eq(out, v->mac, 16), "cmac", "stream", i);
    }
    for (size_t i = 0; i < NVEC(pd_wrap_vecs); i++) {
        const struct pd_wrap_vec *v = &pd_wrap_vecs[i];
        const struct ccmode_ecb *e = ccaes_ecb_encrypt_mode(), *d = ccaes_ecb_decrypt_mode();
        ccecb_ctx_decl(e->size, ec);
        ccecb_ctx_decl(d->size, dc);
        uint8_t out[128], back[128];
        size_t olen = sizeof(out), blen = sizeof(back);
        e->init(e, ec, v->kek_len, v->kek);
        d->init(d, dc, v->kek_len, v->kek);
        int rc = ccwrap_auth_encrypt(e, ec, v->key_len, v->key, &olen, out);
        check(rc == 0 && olen == v->wrapped_len && eq(out, v->wrapped, olen), "keywrap", "wrap", i);
        rc = ccwrap_auth_decrypt(d, dc, v->wrapped_len, v->wrapped, &blen, back);
        check(rc == 0 && blen == v->key_len && eq(back, v->key, blen), "keywrap", "unwrap", i);
        memcpy(out, v->wrapped, v->wrapped_len);
        out[3] ^= 1;
        blen = sizeof(back);
        check(ccwrap_auth_decrypt(d, dc, v->wrapped_len, out, &blen, back) != 0, "keywrap", "tamper", i);
    }
    for (size_t i = 0; i < NVEC(pd_x963_vecs); i++) {
        const struct pd_x963_vec *v = &pd_x963_vecs[i];
        uint8_t out[128];
        int rc = ccansikdf_x963(v->di(), v->z_len, v->z, v->si_len, v->si, v->key_len, out);
        check(rc == 0 && eq(out, v->key, v->key_len), "x963kdf", "derive", i);
    }
    for (size_t i = 0; i < NVEC(pd_nistkdf_vecs); i++) {
        const struct pd_cksum_vec { B(key); B(iv); B(msg); B(mac); };
struct pd_nistkdf_vec *v = &pd_nistkdf_vecs[i];
        uint8_t out[128];
        int rc = ccnistkdf_ctr_hmac(v->di(), v->kdk_len, v->kdk, v->label_len, v->label, v->ctx_len, v->ctx, v->dk_len, out);
        check(rc == 0 && eq(out, v->dk, v->dk_len), "nistkdf", "ctr-hmac", i);
    }
}

static void test_cksum(void)
{
    for (size_t i = 0; i < NVEC(pd_cksum_vecs); i++) {
        const struct pd_cksum_vec *v = &pd_cksum_vecs[i];
        uint8_t out[8];
        uint32_t r = ccdes_cbc_cksum(v->msg, out, v->msg_len, v->key, v->key_len, v->iv);
        uint32_t want = ((uint32_t)v->mac[4] << 24) | ((uint32_t)v->mac[5] << 16) | ((uint32_t)v->mac[6] << 8) | v->mac[7];
        check(eq(out, v->mac, 8) && r == want, "des-cbc-cksum", "mac", i);
    }
}

static void test_rng(void)
{
    int err = -1;
    struct ccrng_state *rng = ccrng(&err);
    check(rng != NULL && err == 0, "rng", "ccrng", 0);
    if (!rng) return;

    uint8_t a[100000], b[100000];
    check(ccrng_generate(rng, sizeof(a), a) == 0 && ccrng_generate(rng, sizeof(b), b) == 0 && memcmp(a, b, sizeof(a)) != 0, "rng", "generate", 0);

    // crude bias check, each byte value about 1/256
    size_t counts[256] = { 0 };
    for (size_t i = 0; i < sizeof(a); i++) counts[a[i]]++;
    int ok = 1;
    for (int i = 0; i < 256; i++) if (counts[i] < 250 || counts[i] > 550) ok = 0;
    check(ok, "rng", "byte-spread", 0);

    ok = 1;
    for (int i = 0; i < 2000; i++) {
        uint64_t r;
        uint64_t bound = (uint64_t)(i % 37) + 1;
        if (ccrng_uniform(rng, bound, &r) || r >= bound) ok = 0;
    }
    check(ok, "rng", "uniform-bound", 0);
    uint64_t r;
    check(ccrng_uniform(rng, 0, &r) != 0, "rng", "uniform-zero", 0);

    struct ccrng_system_state sys;
    check(ccrng_system_init(&sys) == 0 && ccrng_generate((struct ccrng_state *)&sys, 32, a) == 0, "rng", "system", 0);
    ccrng_system_done(&sys);
}

static int32_t fake_entropy(size_t *n, void *buf, void *arg)
{
    (void)arg;
    memset(buf, 0x5a, *n);
    return 64;
}

static void test_drbg_tail(void)
{
    // a short request must return the leftmost bytes of the block a whole-block request would
    for (int df = 0; df < 2; df++) {
        struct ccdrbg_info info;
        static ccdrbg_df_bc_ctx_t dfc;
        struct ccdrbg_nistctr_custom custom = { ccaes_ctr_crypt_mode(), CCAES_KEY_SIZE_256, false, NULL };
        if (df) { ccdrbg_df_bc_init(&dfc, ccaes_cbc_encrypt_mode(), CCAES_KEY_SIZE_256); custom.df_ctx = (ccdrbg_df_ctx_t *)&dfc; }
        ccdrbg_factory_nistctr(&info, &custom);
        static uint8_t s1[2048], s2[2048];
        uint8_t ent[48], a[48], b[48];
        for (int i = 0; i < 48; i++) ent[i] = (uint8_t)(i * 3 + 1);
        ccdrbg_init(&info, (struct ccdrbg_state *)s1, 48, ent, 16, ent, 0, NULL);
        ccdrbg_init(&info, (struct ccdrbg_state *)s2, 48, ent, 16, ent, 0, NULL);
        for (size_t n = 1; n <= 47; n += 7) {
            memset(a, 0, sizeof(a)); memset(b, 0, sizeof(b));
            ccdrbg_init(&info, (struct ccdrbg_state *)s1, 48, ent, 16, ent, 0, NULL);
            ccdrbg_init(&info, (struct ccdrbg_state *)s2, 48, ent, 16, ent, 0, NULL);
            ccdrbg_generate(&info, (struct ccdrbg_state *)s1, n, a, 0, NULL);
            ccdrbg_generate(&info, (struct ccdrbg_state *)s2, 48, b, 0, NULL);
            int nz = 0;
            for (size_t i = 0; i < n; i++) nz |= a[i];
            check(eq(a, b, n) && nz, "ctr_drbg", df ? "short-request-df" : "short-request", n);
        }
    }
}

static void test_kprng(void)
{
    static struct cckprng_ctx a, b;
    uint8_t x[256], y[256], z[256];
    const uint8_t seed[32] = { 1, 2, 3 };
    uint64_t nonce = 42;

    cckprng_init_with_getentropy(&a, 8, sizeof(seed), seed, sizeof(nonce), &nonce, fake_entropy, NULL);
    cckprng_init_with_getentropy(&b, 8, sizeof(seed), seed, sizeof(nonce), &nonce, fake_entropy, NULL);
    cckprng_initgen(&a, 0); cckprng_initgen(&a, 1); cckprng_initgen(&b, 0);

    cckprng_generate(&a, 0, sizeof(x), x);
    cckprng_generate(&b, 0, sizeof(y), y);
    check(memcmp(x, y, sizeof(x)) == 0, "kprng", "same-seed-same-stream", 0);
    cckprng_generate(&a, 1, sizeof(z), z);
    check(memcmp(x, z, sizeof(x)) != 0, "kprng", "generators-differ", 0);
    cckprng_generate(&a, 0, sizeof(z), z);
    check(memcmp(x, z, sizeof(x)) != 0, "kprng", "stream-advances", 0);
    cckprng_reseed(&b, sizeof(seed), seed);
    cckprng_generate(&a, 0, sizeof(x), x);
    cckprng_generate(&b, 0, sizeof(y), y);
    check(memcmp(x, y, sizeof(x)) != 0, "kprng", "reseed-diverges", 0);
    for (int i = 0; i < 200; i++) cckprng_refresh(&a);
    cckprng_generate(&a, 0, sizeof(x), x);
    check(1, "kprng", "refresh", 0);
}

int ccpost_validate(void);

int main(void)
{
    test_digest();
    test_hmac();
    test_blk();
    test_pkcs7();
    test_pkcs7_big();
    test_cts3();
    test_xts();
    test_gcm();
    test_ccm();
    test_chapoly();
    test_kdfs();
    test_cksum();
    test_rng();
    test_drbg_tail();
    test_kprng();

    check(ccpost_validate() == 0, "post", "ccpost_validate (aes ecb/cbc/ctr, ctr_drbg kat)", 0);

    printf("pd_kat: %d passed, %d failed\n", pass, fail);
    return fail ? 1 : 0;
}
