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
#include <corecrypto/ccnistkdf.h>
#include <corecrypto/cc_memory.h>

// k(i) = prf(kdk, [i]_32 || fixed data), counter before the fixed data (sp 800-108 5.1)
int ccnistkdf_ctr_hmac_fixed(const struct ccdigest_info *di,
                             size_t kdkLen, const void *kdk,
                             size_t fixedDataLen, const void *fixedData,
                             size_t dkLen, void *dk)
{
    size_t hlen = di->output_size;
    uint8_t k[MAX_DIGEST_OUTPUT_SIZE];
    uint8_t *out = dk;
    cchmac_di_decl(di, ctx);

    if (hlen > sizeof(k)) return CCERR_PARAMETER;
    if (dkLen == 0 || (dkLen + hlen - 1) / hlen > 0xffffffffULL) return CCERR_PARAMETER;

    for (uint32_t i = 1; dkLen; i++) {
        uint8_t be[4] = { (uint8_t)(i >> 24), (uint8_t)(i >> 16), (uint8_t)(i >> 8), (uint8_t)i };

        cchmac_init(di, ctx, kdkLen, kdk);
        cchmac_update(di, ctx, 4, be);
        cchmac_update(di, ctx, fixedDataLen, fixedData);
        cchmac_final(di, ctx, k);

        size_t take = dkLen < hlen ? dkLen : hlen;
        cc_copy(take, out, k);
        out += take;
        dkLen -= take;
    }

    cchmac_di_clear(di, ctx);
    cc_clear(sizeof(k), k);
    return CCERR_OK;
}

// fixed data = label || 0x00 || context || [l]_32 with l in bits (sp 800-108 5)
int ccnistkdf_ctr_hmac(const struct ccdigest_info *di,
                       size_t kdkLen, const void *kdk,
                       size_t labelLen, const void *label,
                       size_t contextLen, const void *context,
                       size_t dkLen, void *dk)
{
    size_t fixedLen = labelLen + 1 + contextLen + 4;
    uint64_t bits = (uint64_t)dkLen * 8;
    int rc;

    if (bits > 0xffffffffULL) return CCERR_PARAMETER;

    uint8_t *fixed = cc_heap_allocate(fixedLen);
    if (fixed == NULL) return CCERR_MEMORY;

    if (labelLen) cc_copy(labelLen, fixed, label);
    fixed[labelLen] = 0;
    if (contextLen) cc_copy(contextLen, fixed + labelLen + 1, context);
    for (int i = 0; i < 4; i++) {
        fixed[fixedLen - 1 - i] = (uint8_t)(bits >> (8 * i));
    }

    rc = ccnistkdf_ctr_hmac_fixed(di, kdkLen, kdk, fixedLen, fixed, dkLen, dk);

    cc_clear(fixedLen, fixed);
    cc_heap_free(fixed, fixedLen);
    return rc;
}
