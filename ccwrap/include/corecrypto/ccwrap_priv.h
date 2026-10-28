/*
 * Copyright (C) 2026, PureDarwin contributors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CCWRAP_PRIV_H__
#define __CORECRYPTO_CCWRAP_PRIV_H__

#include <corecrypto/ccmode.h>

CC_BEGIN_DECLS

#define CCWRAP_SEMIBLOCK 8

// aes key wrap (rfc 3394, sp 800-38f kw)
CC_EXPORT int ccwrap_auth_decrypt_withiv(const struct ccmode_ecb *mode, ccecb_ctx *ctx, size_t wrappedLen, const void *wrappedKey,
                                         size_t *unwrappedLen, void *unwrappedKey, const void *iv);
CC_EXPORT int ccwrap_auth_encrypt_withiv(const struct ccmode_ecb *mode, ccecb_ctx *ctx, size_t unwrappedLen, const void *unwrappedKey,
                                         size_t *wrappedLen, void *wrappedKey, const void *iv);
CC_EXPORT int ccwrap_auth_decrypt(const struct ccmode_ecb *mode, ccecb_ctx *ctx, size_t wrappedLen, const void *wrappedKey,
                                  size_t *unwrappedLen, void *unwrappedKey);
CC_EXPORT int ccwrap_auth_encrypt(const struct ccmode_ecb *mode, ccecb_ctx *ctx, size_t unwrappedLen, const void *unwrappedKey,
                                  size_t *wrappedLen, void *wrappedKey);
CC_EXPORT size_t ccwrap_unwrapped_size(size_t wrappedLen);
CC_EXPORT size_t ccwrap_wrapped_size(size_t unwrappedLen);

CC_END_DECLS

#endif /* __CORECRYPTO_CCWRAP_PRIV_H__ */
