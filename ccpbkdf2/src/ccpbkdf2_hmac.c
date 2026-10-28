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
#include <corecrypto/ccpbkdf2.h>

// dk = t_1 || t_2 || ..., t_i = u_1 xor ... xor u_c, u_1 = prf(p, s || int(i)) (rfc 8018 5.2)
int ccpbkdf2_hmac(const struct ccdigest_info *di,
                  size_t passwordLen, const void *password,
                  size_t saltLen, const void *salt,
                  size_t iterations,
                  size_t dkLen, void *dk)
{
    size_t hlen = di->output_size;
    uint8_t *out = dk;
    uint8_t u[MAX_DIGEST_OUTPUT_SIZE], t[MAX_DIGEST_OUTPUT_SIZE];
    cchmac_di_decl(di, keyed);
    cchmac_di_decl(di, work);

    if (iterations == 0) return CCERR_PARAMETER;
    if (dkLen == 0) return CCERR_OK;
    if (hlen > sizeof(u)) return CCERR_PARAMETER;
    if ((dkLen + hlen - 1) / hlen > 0xffffffffULL) return CCERR_PARAMETER;

    // key the hmac once, then copy the keyed state per block
    cchmac_init(di, keyed, passwordLen, password);

    for (uint32_t block = 1; dkLen; block++) {
        uint8_t be[4] = { (uint8_t)(block >> 24), (uint8_t)(block >> 16), (uint8_t)(block >> 8), (uint8_t)block };

        cc_copy(cchmac_di_size(di), work, keyed);
        cchmac_update(di, work, saltLen, salt);
        cchmac_update(di, work, 4, be);
        cchmac_final(di, work, u);
        cc_copy(hlen, t, u);

        for (size_t j = 1; j < iterations; j++) {
            cc_copy(cchmac_di_size(di), work, keyed);
            cchmac_update(di, work, hlen, u);
            cchmac_final(di, work, u);
            cc_xor(hlen, t, t, u);
        }

        size_t take = dkLen < hlen ? dkLen : hlen;
        cc_copy(take, out, t);
        out += take;
        dkLen -= take;
    }

    cchmac_di_clear(di, keyed);
    cchmac_di_clear(di, work);
    cc_clear(sizeof(u), u);
    cc_clear(sizeof(t), t);
    return CCERR_OK;
}
