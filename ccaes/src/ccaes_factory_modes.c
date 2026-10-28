/*
 * Copyright (C) 2026, PureDarwin contributors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

// pd interim LLM-written code, experimental and not secure: unaudited, unfuzzed, no side-channel review
#include <corecrypto/ccaes.h>
#include <corecrypto/ccmode_factory.h>
#include <corecrypto/ccmode_internal.h>

// aes feedback and aead modes over the generic factories
CCMODE_STREAM_FACTORY(aes, cfb, encrypt)
CCMODE_STREAM_FACTORY(aes, cfb, decrypt)
CCMODE_STREAM_FACTORY(aes, cfb8, encrypt)
CCMODE_STREAM_FACTORY(aes, cfb8, decrypt)
CCMODE_OFB_FACTORY(aes)
CCMODE_GCM_FACTORY(aes, encrypt)
CCMODE_GCM_FACTORY(aes, decrypt)
CCMODE_CCM_FACTORY(aes, encrypt)
CCMODE_CCM_FACTORY(aes, decrypt)
