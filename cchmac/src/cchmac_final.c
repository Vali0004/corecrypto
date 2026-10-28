/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <corecrypto/ccdigest_priv.h>
#include <corecrypto/cchmac.h>

void cchmac_final(const struct ccdigest_info *di,
                  cchmac_ctx_t ctx,
                  void *mac)
{
    /* We've already partially done the opad state earlier, let's finish what we started. */
    ccdigest_final(di, cchmac_digest_ctx(di, ctx), cchmac_data(di, ctx));
    
    // outer hash over the inner digest from the opad state (rfc 2104 2)
    cchmac_num(di, ctx) = (uint32_t)di->output_size;
    cchmac_nbits(di, ctx) = (di->block_size << 3);
    
    ccdigest_copy_state(di, cchmac_istate(di, ctx), cchmac_ostate(di, ctx));
    ccdigest_final(di, cchmac_digest_ctx(di, ctx), mac);
}
