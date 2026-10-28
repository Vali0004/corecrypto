/*
 * Copyright (C) 2026, PureDarwin contributors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CCHKDF_H__
#define __CORECRYPTO_CCHKDF_H__

#include <corecrypto/ccdigest.h>

CC_BEGIN_DECLS

// hmac-based extract-and-expand kdf (rfc 5869)
CC_EXPORT int cchkdf(const struct ccdigest_info *di, size_t ikmLen, const void *ikm,
                     size_t saltLen, const void *salt, size_t infoLen, const void *info,
                     size_t dkLen, void *dk);
CC_EXPORT int cchkdf_extract(const struct ccdigest_info *di, size_t saltLen, const void *salt,
                             size_t keyDerivationKeyLen, const void *keyDerivationKey, void *prk);
CC_EXPORT int cchkdf_expand(const struct ccdigest_info *di, size_t prkLen, const void *prk,
                            size_t contextLen, const void *context, size_t derivedKeyLen, void *derivedKey);

CC_END_DECLS

#endif /* __CORECRYPTO_CCHKDF_H__ */
