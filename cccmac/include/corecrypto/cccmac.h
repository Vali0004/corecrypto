/*
 * Copyright (C) 2026, PureDarwin contributors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CCCMAC_H__
#define __CORECRYPTO_CCCMAC_H__

#include <corecrypto/ccmode.h>
#include <corecrypto/ccn.h>

CC_BEGIN_DECLS

#define CMAC_BLOCKSIZE 16

// same size as the shipped interface header, the inside is private
struct cccmac_ctx {
    uint8_t k1[16];
    uint8_t k2[16];
    uint8_t ctx[8];
} __attribute__((aligned(8)));
typedef struct cccmac_ctx *cccmac_ctx_t;

#define cccmac_hdr_size sizeof(struct cccmac_ctx)
#define cccmac_iv_size(_mode_)  ((_mode_)->block_size)
#define cccmac_cbc_size(_mode_) ((_mode_)->size)
#define cccmac_ctx_size(_mode_) (cccmac_hdr_size + cccmac_iv_size(_mode_) + cccmac_cbc_size(_mode_))
#define cccmac_ctx_n(_mode_)  ccn_nof_size(cccmac_ctx_size(_mode_))
#define cccmac_mode_decl(_mode_, _name_) cc_ctx_decl(struct cccmac_ctx, cccmac_ctx_size(_mode_), _name_)
#define cccmac_mode_clear(_mode_, _name_) cc_clear(cccmac_ctx_size(_mode_), _name_)

// aes-cmac (sp 800-38b, rfc 4493)
CC_EXPORT int cccmac_init(const struct ccmode_cbc *cbc, cccmac_ctx_t ctx, size_t key_length, const void *key);
CC_EXPORT int cccmac_update(cccmac_ctx_t ctx, size_t data_length, const void *data);
CC_EXPORT int cccmac_final_generate(cccmac_ctx_t ctx, size_t mac_length, void *mac);
CC_EXPORT int cccmac_final_verify(cccmac_ctx_t ctx, size_t expected_mac_length, const void *expected_mac);
CC_EXPORT int cccmac_one_shot_generate(const struct ccmode_cbc *cbc, size_t key_length, const void *key,
                                       size_t data_length, const void *data, size_t mac_length, void *mac);
CC_EXPORT int cccmac_one_shot_verify(const struct ccmode_cbc *cbc, size_t key_length, const void *key,
                                     size_t data_length, const void *data, size_t expected_mac_length, const void *expected_mac);
CC_EXPORT const struct ccmode_cbc *cccmac_cbc(cccmac_ctx_t ctx);

CC_END_DECLS

#endif /* __CORECRYPTO_CCCMAC_H__ */
