/*
 * Copyright (C) 2026, PureDarwin contributors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

// pd interim LLM-written code, experimental and not secure: unaudited, unfuzzed, no side-channel review
#include <corecrypto/cc_priv.h>
#include <corecrypto/cchmac.h>
#include <corecrypto/cchkdf.h>

// prk = hmac(salt, ikm), an absent salt is hashlen zero bytes (rfc 5869 2.2)
int cchkdf_extract(const struct ccdigest_info *di, size_t saltLen, const void *salt,
                   size_t keyDerivationKeyLen, const void *keyDerivationKey, void *prk)
{
    uint8_t zeros[MAX_DIGEST_OUTPUT_SIZE] = { 0 };

    if (di->output_size > sizeof(zeros)) return CCERR_PARAMETER;
    if (saltLen == 0) {
        salt = zeros;
        saltLen = di->output_size;
    }
    cchmac(di, saltLen, salt, keyDerivationKeyLen, keyDerivationKey, prk);
    return CCERR_OK;
}

// t(i) = hmac(prk, t(i-1) || info || i), at most 255 blocks (rfc 5869 2.3)
int cchkdf_expand(const struct ccdigest_info *di, size_t prkLen, const void *prk,
                  size_t contextLen, const void *context, size_t derivedKeyLen, void *derivedKey)
{
    size_t hlen = di->output_size;
    uint8_t t[MAX_DIGEST_OUTPUT_SIZE];
    uint8_t *out = derivedKey;
    size_t tlen = 0;
    cchmac_di_decl(di, ctx);

    if (hlen > sizeof(t)) return CCERR_PARAMETER;
    if (derivedKeyLen > 255 * hlen) return CCERR_PARAMETER;

    for (uint8_t i = 1; derivedKeyLen; i++) {
        cchmac_init(di, ctx, prkLen, prk);
        cchmac_update(di, ctx, tlen, t);
        cchmac_update(di, ctx, contextLen, context);
        cchmac_update(di, ctx, 1, &i);
        cchmac_final(di, ctx, t);
        tlen = hlen;

        size_t take = derivedKeyLen < hlen ? derivedKeyLen : hlen;
        cc_copy(take, out, t);
        out += take;
        derivedKeyLen -= take;
    }

    cchmac_di_clear(di, ctx);
    cc_clear(sizeof(t), t);
    return CCERR_OK;
}

int cchkdf(const struct ccdigest_info *di, size_t ikmLen, const void *ikm,
           size_t saltLen, const void *salt, size_t infoLen, const void *info,
           size_t dkLen, void *dk)
{
    uint8_t prk[MAX_DIGEST_OUTPUT_SIZE];
    int rc = cchkdf_extract(di, saltLen, salt, ikmLen, ikm, prk);
    if (rc == 0) rc = cchkdf_expand(di, di->output_size, prk, infoLen, info, dkLen, dk);
    cc_clear(sizeof(prk), prk);
    return rc;
}
