/*
 * Copyright (C) 2026, PureDarwin contributors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CCRIPEMD_H__
#define __CORECRYPTO_CCRIPEMD_H__

#include <corecrypto/ccdigest.h>

CC_BEGIN_DECLS

#define CCRMD160_BLOCK_SIZE   64
#define CCRMD160_OUTPUT_SIZE  20
#define CCRMD160_STATE_SIZE   20

CC_EXPORT const struct ccdigest_info ccrmd160_ltc_di;

#define ccrmd160_di ccrmd160_ltc_di

CC_END_DECLS

#endif /* __CORECRYPTO_CCRIPEMD_H__ */
