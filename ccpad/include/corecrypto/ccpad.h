/*
 * Copyright (C) 2026, PureDarwin contributors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CCPAD_H__
#define __CORECRYPTO_CCPAD_H__

#include <corecrypto/ccmode.h>

CC_BEGIN_DECLS

// ciphertext stealing variants cs1, cs2, cs3 (sp 800-38a addendum), nbytes is at least one block plus one byte
CC_EXPORT size_t ccpad_cts1_decrypt(const struct ccmode_cbc *cbc, cccbc_ctx *ctx, cccbc_iv *iv, size_t nbytes, const void *in, void *out);
CC_EXPORT size_t ccpad_cts1_encrypt(const struct ccmode_cbc *cbc, cccbc_ctx *ctx, cccbc_iv *iv, size_t nbytes, const void *in, void *out);
CC_EXPORT size_t ccpad_cts2_decrypt(const struct ccmode_cbc *cbc, cccbc_ctx *ctx, cccbc_iv *iv, size_t nbytes, const void *in, void *out);
CC_EXPORT size_t ccpad_cts2_encrypt(const struct ccmode_cbc *cbc, cccbc_ctx *ctx, cccbc_iv *iv, size_t nbytes, const void *in, void *out);
CC_EXPORT size_t ccpad_cts3_decrypt(const struct ccmode_cbc *cbc, cccbc_ctx *ctx, cccbc_iv *iv, size_t nbytes, const void *in, void *out);
CC_EXPORT size_t ccpad_cts3_encrypt(const struct ccmode_cbc *cbc, cccbc_ctx *ctx, cccbc_iv *iv, size_t nbytes, const void *in, void *out);

// pkcs#7 padding (rfc 5652 6.3), decrypt returns the unpadded length
CC_EXPORT size_t ccpad_pkcs7_decrypt(const struct ccmode_cbc *cbc, cccbc_ctx *ctx, cccbc_iv *iv, size_t nbytes, const void *in, void *out);
CC_EXPORT size_t ccpad_pkcs7_encrypt(const struct ccmode_cbc *cbc, cccbc_ctx *ctx, cccbc_iv *iv, size_t nbytes, const void *in, void *out);
CC_EXPORT size_t ccpad_pkcs7_ecb_decrypt(const struct ccmode_ecb *ecb, ccecb_ctx *ecb_key, size_t nbytes, const void *in, void *out);
CC_EXPORT size_t ccpad_pkcs7_ecb_encrypt(const struct ccmode_ecb *ecb, ccecb_ctx *ctx, size_t nbytes, const void *in, void *out);
CC_EXPORT size_t ccpad_pkcs7_decode(const size_t block_size, const uint8_t *last_block);

// xts ciphertext stealing (sp 800-38e, ieee 1619 5.3)
CC_EXPORT size_t ccpad_xts_decrypt(const struct ccmode_xts *xts, ccxts_ctx *ctx, ccxts_tweak *tweak, size_t nbytes, const void *in, void *out);
CC_EXPORT void ccpad_xts_encrypt(const struct ccmode_xts *xts, ccxts_ctx *ctx, ccxts_tweak *tweak, size_t nbytes, const void *in, void *out);

CC_END_DECLS

#endif /* __CORECRYPTO_CCPAD_H__ */
