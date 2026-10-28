/*
 * Copyright (C) 2026, PureDarwin contributors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
// pd interim LLM-written code, experimental and not secure: unaudited, unfuzzed, no side-channel review

#include <corecrypto/cc_priv.h>
#include <corecrypto/ccmode_internal.h>

static uint64_t load64_be(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v = (v << 8) | p[i];
    }
    return v;
}

static void store64_be(uint8_t *p, uint64_t v)
{
    for (int i = 7; i >= 0; i--) {
        p[i] = (uint8_t)v;
        v >>= 8;
    }
}

// x = x * h in gf(2^128), right-shift multiply (sp 800-38d 6.3, algorithm 1)
void ccmode_gcm_gf_mult_h(const uint8_t h[16], uint8_t x[16])
{
    uint64_t vh = load64_be(h), vl = load64_be(h + 8);
    uint64_t zh = 0, zl = 0;

    for (int i = 0; i < 128; i++) {
        uint64_t bit = (uint64_t)((x[i >> 3] >> (7 - (i & 7))) & 1);
        uint64_t mask = 0 - bit;
        zh ^= vh & mask;
        zl ^= vl & mask;

        uint64_t lsb = 0 - (vl & 1);
        vl = (vl >> 1) | (vh << 63);
        vh = (vh >> 1) ^ (0xe100000000000000ULL & lsb);
    }

    store64_be(x, zh);
    store64_be(x + 8, zl);
}

// ghash over whole blocks, the caller pads the tail (sp 800-38d 6.4, algorithm 2)
void ccmode_gcm_ghash(struct _ccmode_gcm_key *key, size_t nbytes, const uint8_t *in)
{
    while (nbytes >= 16) {
        cc_xor(16, key->X, key->X, in);
        ccmode_gcm_gf_mult_h(key->H, key->X);
        in += 16;
        nbytes -= 16;
    }
}
