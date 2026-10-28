/*
 * Copyright (C) 2026, PureDarwin contributors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CCANSIKDF_H__
#define __CORECRYPTO_CCANSIKDF_H__

#include <corecrypto/ccdigest.h>

CC_BEGIN_DECLS

// ansi x9.63 kdf (sec 1 v2 3.6.1)
CC_EXPORT int ccansikdf_x963(const struct ccdigest_info *di,
                             const size_t Z_len, const unsigned char *Z,
                             const size_t sharedinfo_byte_len, const void *sharedinfo,
                             const size_t key_len, uint8_t *key);

CC_END_DECLS

#endif /* __CORECRYPTO_CCANSIKDF_H__ */
