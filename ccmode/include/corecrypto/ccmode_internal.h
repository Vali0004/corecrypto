/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CCMODE_INTERNAL_H__
#define __CORECRYPTO_CCMODE_INTERNAL_H__

#include <corecrypto/ccmode.h>
#include <corecrypto/ccmode_factory.h>
#include <corecrypto/ccn.h>
#include <corecrypto/cc_priv.h>

CC_BEGIN_DECLS

CC_INLINE void inc_uint_be(uint8_t *ptr, size_t len)
{
    for (size_t i = 1; i <= len; i += 1) {
        size_t j = len - i;
        ptr[j] = (uint8_t)(ptr[j] + 1);
        if (ptr[j] > 0) {
            return;
        }
    }
}

/*
 * Default CBC implementation.
 *
 * Since this defines the function interface too, we mark the struct as READ_ONLY_LATE for platforms
 * that use it.
 */
#define CCMODE_CBC_FACTORY(cipher, encdec)                                  \
    static CC_READ_ONLY_LATE(struct ccmode_cbc) cbc_##cipher##_##encdec;    \
                                                                            \
    const struct ccmode_cbc *cc##cipher##_cbc_##encdec##_mode(void) {       \
        const struct ccmode_ecb *ecb=cc##cipher##_ecb_##encdec##_mode();    \
        ccmode_factory_cbc_##encdec(&cbc_##cipher##_##encdec, ecb);         \
        return &cbc_##cipher##_##encdec;                                    \
    }                                                                       \

cc_error_t ccmode_cbc_init(const struct ccmode_cbc *cbc,
                           cccbc_ctx *ctx,
                           size_t rk_len,
                           const void *rk);

cc_error_t ccmode_cbc_decrypt(const cccbc_ctx *ctx,
                              cccbc_iv *iv,
                              size_t nblocks,
                              const void *in,
                              void *out);

cc_error_t ccmode_cbc_encrypt(const cccbc_ctx *ctx,
                              cccbc_iv *iv,
                              size_t nblocks,
                              const void *in,
                              void *out);

struct _ccmode_cbc_key {
    const struct ccmode_ecb *ecb;
    cc_unit u[];
};

#define CCMODE_CBC_KEY(key)         ((struct _ccmode_cbc_key *)key)
#define CCMODE_CBC_KEY_ECB(key)     CCMODE_CBC_KEY(key)->ecb
#define CCMODE_CBC_KEY_ECB_CTX(key) (ccecb_ctx *)(&CCMODE_CBC_KEY(key)->u[0])

/*
 * Default CTR implementation
 *
 * Since this defines the function interface too, we mark the struct as READ_ONLY_LATE for platforms
 * that use it.
 */
#define CCMODE_CTR_FACTORY(cipher)                                          \
    static CC_READ_ONLY_LATE(struct ccmode_ctr) ctr_##cipher;               \
                                                                            \
    const struct ccmode_ctr *cc##cipher##_ctr_crypt_mode(void) {            \
        const struct ccmode_ecb *ecb=cc##cipher##_ecb_encrypt_mode();       \
        ccmode_factory_ctr_crypt(&ctr_##cipher, ecb);                       \
        return &ctr_##cipher;                                               \
    }                                                                       \

struct _ccmode_ctr_key {
    const struct ccmode_ecb *ecb;
    size_t pad_len;

    /*
     * layout:
     * counter  [ block_size ]          corecrypto counters are always 8 bytes in length at the end of the block.
     * pad      [ block_size ]
     * ecb_ctx  [ ecb ctx size ]
     */
    cc_unit u[];
};

cc_error_t ccmode_ctr_init(const struct ccmode_ctr *ctr,
                           ccctr_ctx *ctx,
                           size_t key_size,
                           const void *key,
                           const void *iv);

cc_error_t ccmode_ctr_setctr(const struct ccmode_ctr *ctr,
                             ccctr_ctx *ctx,
                             const void *counter);

cc_error_t ccmode_ctr_crypt(ccctr_ctx *ctx,
                            size_t nbytes,
                            const void *in,
                            void *out);

#define CCMODE_CTR_KEY(key)             ((struct _ccmode_ctr_key *)key)
#define CCMODE_CTR_KEY_ECB(key)         CCMODE_CTR_KEY(key)->ecb
#define CCMODE_CTR_KEY_COUNTER(key)     (uint8_t *)(&CCMODE_CTR_KEY(key)->u[0])
#define CCMODE_CTR_KEY_PAD_LENGTH(key)  (CCMODE_CTR_KEY(key)->pad_len)
#define CCMODE_CTR_KEY_PAD(key)         (uint8_t *)(&CCMODE_CTR_KEY(key)->u[ccn_nof_size(CCMODE_CTR_KEY_ECB(key)->block_size)])
#define CCMODE_CTR_KEY_ECB_CTX(key)     (ccecb_ctx *)(&CCMODE_CTR_KEY(key)->u[ccn_nof_size(CCMODE_CTR_KEY_ECB(key)->block_size * 2)])

/*
 * Default XTS implementation
 *
 * Since this defines the function interface too, we mark the struct as READ_ONLY_LATE for platforms
 * that use it.
 */
#define CCMODE_XTS_FACTORY(cipher, encdec)                                      \
    static CC_READ_ONLY_LATE(struct ccmode_xts) xts_##cipher##_##encdec;        \
                                                                                \
    const struct ccmode_xts *cc##cipher##_xts_##encdec##_mode(void) {           \
        const struct ccmode_ecb *ecb=cc##cipher##_ecb_##encdec##_mode();        \
        const struct ccmode_ecb *ecb_enc=cc##cipher##_ecb_encrypt_mode();       \
        ccmode_factory_xts_##encdec(&xts_##cipher##_##encdec, ecb, ecb_enc);    \
        return &xts_##cipher##_##encdec;                                        \
    }

struct _ccmode_xts_key {
    const struct ccmode_ecb *ecb;
    const struct ccmode_ecb *ecb_encrypt;

    cc_unit u[];
};

struct _ccmode_xts_tweak {
    size_t blocks_processed;
    cc_unit u[];
};

#define CCMODE_XTS_TWEAK_MAX_BLOCKS_PROCESSED   0x100000

#define CCMODE_XTS_KEY(key)                     ((struct _ccmode_xts_key *)key)
#define CCMODE_XTS_KEY_ECB_MODE(key)            CCMODE_XTS_KEY(key)->ecb
#define CCMODE_XTS_KEY_ECB_CTX(key)             (ccecb_ctx *)&(CCMODE_XTS_KEY(key)->u[0])
#define CCMODE_XTS_KEY_ECB_ENCRYPT_CTX(key)     (ccecb_ctx *)&(CCMODE_XTS_KEY(key)->u[ccn_nof_size(CCMODE_XTS_KEY_ECB_MODE(key)->size)])
#define CCMODE_XTS_KEY_ECB_ENCRYPT_MODE(key)    CCMODE_XTS_KEY(key)->ecb_encrypt

#define CCMODE_XTS_TWEAK(tweak)                     ((struct _ccmode_xts_tweak *)tweak)
#define CCMODE_XTS_TWEAK_BLOCKS_PROCESSED(tweak)    CCMODE_XTS_TWEAK(tweak)->blocks_processed
#define CCMODE_XTS_TWEAK_BUFFER(tweak)              &(CCMODE_XTS_TWEAK(tweak)->u[0])

cc_error_t ccmode_xts_init(const struct ccmode_xts *xts,
                           ccxts_ctx *ctx,
                           size_t key_size,
                           const void *data_key,
                           const void *tweak_key);

cc_error_t ccmode_xts_key_sched(const struct ccmode_xts *xts,
                                ccxts_ctx *ctx,
                                size_t key_size,
                                const void *data_key,
                                const void *tweak_key);

cc_error_t ccmode_xts_set_tweak(const ccxts_ctx *ctx,
                                ccxts_tweak *tweak,
                                const void *iv);

void *ccmode_xts_crypt(const ccxts_ctx *ctx,
                       ccxts_tweak *tweak,
                       size_t nblocks,
                       const void *in,
                       void *out);

// streaming feedback modes (cfb, cfb8, ofb) share one key layout
#define CCMODE_STREAM_FACTORY(cipher, mode, encdec)                             \
    static CC_READ_ONLY_LATE(struct ccmode_##mode) mode##_##cipher##_##encdec;  \
                                                                                \
    const struct ccmode_##mode *cc##cipher##_##mode##_##encdec##_mode(void) {   \
        const struct ccmode_ecb *ecb=cc##cipher##_ecb_encrypt_mode();           \
        ccmode_factory_##mode##_##encdec(&mode##_##cipher##_##encdec, ecb);     \
        return &mode##_##cipher##_##encdec;                                     \
    }

#define CCMODE_OFB_FACTORY(cipher)                                              \
    static CC_READ_ONLY_LATE(struct ccmode_ofb) ofb_##cipher;                   \
                                                                                \
    const struct ccmode_ofb *cc##cipher##_ofb_crypt_mode(void) {                \
        const struct ccmode_ecb *ecb=cc##cipher##_ecb_encrypt_mode();           \
        ccmode_factory_ofb_crypt(&ofb_##cipher, ecb);                           \
        return &ofb_##cipher;                                                   \
    }

// every pre-gcm mode a 64-bit block cipher offers
#define CCMODE_ALL_LEGACY_FACTORIES(cipher)                                     \
    CCMODE_CBC_FACTORY(cipher, encrypt)                                         \
    CCMODE_CBC_FACTORY(cipher, decrypt)                                         \
    CCMODE_CTR_FACTORY(cipher)                                                  \
    CCMODE_STREAM_FACTORY(cipher, cfb, encrypt)                                 \
    CCMODE_STREAM_FACTORY(cipher, cfb, decrypt)                                 \
    CCMODE_STREAM_FACTORY(cipher, cfb8, encrypt)                                \
    CCMODE_STREAM_FACTORY(cipher, cfb8, decrypt)                                \
    CCMODE_OFB_FACTORY(cipher)

struct _ccmode_stream_key {
    const struct ccmode_ecb *ecb;
    size_t offset;
    // layout: register [block], pad [block], ecb ctx
    cc_unit u[];
};

#define CCMODE_STREAM_KEY(key)          ((struct _ccmode_stream_key *)(key))
#define CCMODE_STREAM_KEY_REG(key)      ((uint8_t *)&CCMODE_STREAM_KEY(key)->u[0])
#define CCMODE_STREAM_KEY_PAD(key)      ((uint8_t *)&CCMODE_STREAM_KEY(key)->u[ccn_nof_size(CCMODE_STREAM_KEY(key)->ecb->block_size)])
#define CCMODE_STREAM_KEY_ECB_CTX(key)  ((ccecb_ctx *)&CCMODE_STREAM_KEY(key)->u[2 * ccn_nof_size(CCMODE_STREAM_KEY(key)->ecb->block_size)])

size_t ccmode_stream_ctx_size(const struct ccmode_ecb *ecb);
cc_error_t ccmode_stream_init(const struct ccmode_ecb *ecb, void *ctx, size_t key_size, const void *key, const void *iv);

#define CCMODE_GCM_FACTORY(cipher, encdec)                                      \
    static CC_READ_ONLY_LATE(struct ccmode_gcm) gcm_##cipher##_##encdec;        \
                                                                                \
    const struct ccmode_gcm *cc##cipher##_gcm_##encdec##_mode(void) {           \
        const struct ccmode_ecb *ecb=cc##cipher##_ecb_encrypt_mode();           \
        ccmode_factory_gcm_##encdec(&gcm_##cipher##_##encdec, ecb);             \
        return &gcm_##cipher##_##encdec;                                        \
    }

#define CCMODE_CCM_FACTORY(cipher, encdec)                                      \
    static CC_READ_ONLY_LATE(struct ccmode_ccm) ccm_##cipher##_##encdec;        \
                                                                                \
    const struct ccmode_ccm *cc##cipher##_ccm_##encdec##_mode(void) {           \
        const struct ccmode_ecb *ecb=cc##cipher##_ecb_encrypt_mode();           \
        ccmode_factory_ccm_##encdec(&ccm_##cipher##_##encdec, ecb);             \
        return &ccm_##cipher##_##encdec;                                        \
    }

#define CCGCM_STATE_INIT    1
#define CCGCM_STATE_IV      2
#define CCGCM_STATE_AAD     3
#define CCGCM_STATE_TEXT    4
#define CCGCM_STATE_FINAL   5

struct _ccmode_gcm_key {
    const struct ccmode_ecb *ecb;
    int encdec;
    uint32_t state;
    uint32_t flags;
    uint32_t buf_len;
    uint64_t aad_len;
    uint64_t text_len;
    uint8_t H[16];
    uint8_t J0[16];
    uint8_t Y[16];
    uint8_t X[16];
    uint8_t buf[16];
    uint8_t pad[16];
    cc_unit u[];
};

#define CCGCM_FLAGS_INIT_WITH_IV    1

#define CCMODE_GCM_KEY(key)         ((struct _ccmode_gcm_key *)(key))
#define CCMODE_GCM_KEY_ECB_CTX(key) ((ccecb_ctx *)&CCMODE_GCM_KEY(key)->u[0])

void ccmode_gcm_gf_mult_h(const uint8_t h[16], uint8_t x[16]);
void ccmode_gcm_ghash(struct _ccmode_gcm_key *key, size_t nbytes, const uint8_t *in);

struct _ccmode_ccm_key {
    const struct ccmode_ecb *ecb;
    cc_unit u[];
};


#define CCMODE_CCM_KEY(key)         ((struct _ccmode_ccm_key *)(key))
#define CCMODE_CCM_KEY_ECB_CTX(key) ((ccecb_ctx *)&CCMODE_CCM_KEY(key)->u[0])

CC_END_DECLS

#endif /* __CORECRYPTO_CCMODE_INTERNAL_H__ */
