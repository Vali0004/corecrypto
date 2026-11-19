/*
 * Copyright (C) 2026, PureDarwin contributors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

// pd interim LLM-written code, experimental and not secure: unaudited, unfuzzed, no side-channel review
// ccdh_pd_security.c - the Diffie-Hellman operations Security.framework calls, which fail until they are written
#include <corecrypto/ccdh.h>

int ccdh_generate_key(ccdh_const_gp_t gp, struct ccrng_state *rng, ccdh_full_ctx_t key)
{
    (void)gp; (void)rng; (void)key;
    return CCDH_PD_UNSUPPORTED;
}

int ccdh_import_pub(ccdh_const_gp_t gp, size_t in_len, const uint8_t *in, ccdh_pub_ctx_t key)
{
    (void)gp; (void)in_len; (void)in; (void)key;
    return CCDH_PD_UNSUPPORTED;
}

int ccdh_compute_key(ccdh_full_ctx_t private_key, ccdh_pub_ctx_t public_key, cc_unit *r)
{
    (void)private_key; (void)public_key; (void)r;
    return CCDH_PD_UNSUPPORTED;
}
