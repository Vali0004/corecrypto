/*
 * Copyright (C) 2026, PureDarwin contributors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CCPBKDF2_H__
#define __CORECRYPTO_CCPBKDF2_H__

#include <corecrypto/ccdigest.h>

CC_BEGIN_DECLS

// pbkdf2 with an hmac prf (rfc 8018 5.2)
CC_EXPORT int ccpbkdf2_hmac(const struct ccdigest_info *di,
                            size_t passwordLen, const void *password,
                            size_t saltLen, const void *salt,
                            size_t iterations,
                            size_t dkLen, void *dk);

CC_END_DECLS

#endif /* __CORECRYPTO_CCPBKDF2_H__ */
