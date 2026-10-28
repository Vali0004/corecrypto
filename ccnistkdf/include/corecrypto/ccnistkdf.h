/*
 * Copyright (C) 2026, PureDarwin contributors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CCNISTKDF_H__
#define __CORECRYPTO_CCNISTKDF_H__

#include <corecrypto/ccdigest.h>

CC_BEGIN_DECLS

// counter-mode kdf with an hmac prf (sp 800-108 5.1)
CC_EXPORT int ccnistkdf_ctr_hmac(const struct ccdigest_info *di,
                                 size_t kdkLen, const void *kdk,
                                 size_t labelLen, const void *label,
                                 size_t contextLen, const void *context,
                                 size_t dkLen, void *dk);
CC_EXPORT int ccnistkdf_ctr_hmac_fixed(const struct ccdigest_info *di,
                                       size_t kdkLen, const void *kdk,
                                       size_t fixedDataLen, const void *fixedData,
                                       size_t dkLen, void *dk);

CC_END_DECLS

#endif /* __CORECRYPTO_CCNISTKDF_H__ */
