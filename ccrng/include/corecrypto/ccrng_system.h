/*
 * Copyright (C) 2026, PureDarwin contributors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CCRNG_SYSTEM_H__
#define __CORECRYPTO_CCRNG_SYSTEM_H__

#include <corecrypto/ccrng.h>

CC_BEGIN_DECLS

// deprecated wrapper over ccrng(), kept for existing callers
struct ccrng_system_state {
    cc_error_t (*generate)(struct ccrng_state *rng, size_t out_length, void *out);
    int fd;
};

CC_EXPORT int ccrng_system_init(struct ccrng_system_state *rng);
CC_EXPORT void ccrng_system_done(struct ccrng_system_state *rng);

CC_END_DECLS

#endif /* __CORECRYPTO_CCRNG_SYSTEM_H__ */
