/*
 * Copyright (C) 2026, PureDarwin contributors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

// pd interim LLM-written code, experimental and not secure: unaudited, unfuzzed, no side-channel review
#include <corecrypto/cc_priv.h>
#include <corecrypto/ccwrap_priv.h>

static const uint8_t ccwrap_default_iv[8] = { 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6 };

size_t ccwrap_wrapped_size(size_t unwrappedLen)
{
    return unwrappedLen + CCWRAP_SEMIBLOCK;
}

size_t ccwrap_unwrapped_size(size_t wrappedLen)
{
    return (wrappedLen >= CCWRAP_SEMIBLOCK) ? wrappedLen - CCWRAP_SEMIBLOCK : 0;
}

// wrap with the index-based procedure, 6n steps (rfc 3394 2.2.1)
int ccwrap_auth_encrypt_withiv(const struct ccmode_ecb *mode, ccecb_ctx *ctx, size_t unwrappedLen, const void *unwrappedKey,
                               size_t *wrappedLen, void *wrappedKey, const void *iv)
{
    size_t n = unwrappedLen / 8;
    uint8_t *c = wrappedKey;
    uint8_t b[16];

    if (mode->block_size != 16) return CCERR_PARAMETER;
    if (unwrappedLen % 8 || n < 2 || n > 0x1fffffffULL) return CCERR_PARAMETER;
    if (*wrappedLen < ccwrap_wrapped_size(unwrappedLen)) return CCERR_PARAMETER;

    uint8_t a[8];
    cc_copy(8, a, iv ? iv : ccwrap_default_iv);
    memmove(c + 8, unwrappedKey, unwrappedLen);

    for (size_t j = 0; j <= 5; j++) {
        for (size_t i = 1; i <= n; i++) {
            cc_copy(8, b, a);
            cc_copy(8, b + 8, c + 8 * i);
            mode->ecb(ctx, 1, b, b);

            uint64_t t = (uint64_t)(n * j + i);
            cc_copy(8, a, b);
            for (int k = 0; k < 8; k++) a[7 - k] ^= (uint8_t)(t >> (8 * k));
            cc_copy(8, c + 8 * i, b + 8);
        }
    }

    cc_copy(8, c, a);
    *wrappedLen = ccwrap_wrapped_size(unwrappedLen);
    cc_clear(sizeof(b), b);
    return CCERR_OK;
}

// unwrap and check the integrity value (rfc 3394 2.2.2, 2.2.3)
int ccwrap_auth_decrypt_withiv(const struct ccmode_ecb *mode, ccecb_ctx *ctx, size_t wrappedLen, const void *wrappedKey,
                               size_t *unwrappedLen, void *unwrappedKey, const void *iv)
{
    const uint8_t *c = wrappedKey;
    uint8_t *p = unwrappedKey;
    uint8_t a[8], b[16];

    if (mode->block_size != 16) return CCERR_PARAMETER;
    if (wrappedLen % 8 || wrappedLen < 24) return CCERR_PARAMETER;

    size_t n = wrappedLen / 8 - 1;
    if (*unwrappedLen < n * 8) return CCERR_PARAMETER;

    cc_copy(8, a, c);
    memmove(p, c + 8, n * 8);

    for (size_t j = 6; j-- > 0;) {
        for (size_t i = n; i >= 1; i--) {
            uint64_t t = (uint64_t)(n * j + i);
            cc_copy(8, b, a);
            for (int k = 0; k < 8; k++) b[7 - k] ^= (uint8_t)(t >> (8 * k));
            cc_copy(8, b + 8, p + 8 * (i - 1));
            mode->ecb(ctx, 1, b, b);
            cc_copy(8, a, b);
            cc_copy(8, p + 8 * (i - 1), b + 8);
        }
    }

    cc_clear(sizeof(b), b);
    if (cc_cmp_safe(8, a, iv ? iv : ccwrap_default_iv)) {
        cc_clear(n * 8, p);
        return CCERR_INTEGRITY;
    }

    *unwrappedLen = n * 8;
    return CCERR_OK;
}

int ccwrap_auth_encrypt(const struct ccmode_ecb *mode, ccecb_ctx *ctx, size_t unwrappedLen, const void *unwrappedKey,
                        size_t *wrappedLen, void *wrappedKey)
{
    return ccwrap_auth_encrypt_withiv(mode, ctx, unwrappedLen, unwrappedKey, wrappedLen, wrappedKey, ccwrap_default_iv);
}

int ccwrap_auth_decrypt(const struct ccmode_ecb *mode, ccecb_ctx *ctx, size_t wrappedLen, const void *wrappedKey,
                        size_t *unwrappedLen, void *unwrappedKey)
{
    return ccwrap_auth_decrypt_withiv(mode, ctx, wrappedLen, wrappedKey, unwrappedLen, unwrappedKey, ccwrap_default_iv);
}
