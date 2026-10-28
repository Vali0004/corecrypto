/*
 * Copyright (C) 2026, PureDarwin contributors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

// pd interim LLM-written code, experimental and not secure: unaudited, unfuzzed, no side-channel review
#include <corecrypto/ccdigest_internal.h>
#include <corecrypto/ccripemd.h>

// ripemd-160 (dobbertin, bosselaers, preneel 1996, iso/iec 10118-3)

static const uint8_t rl[80] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
};

static const uint8_t rr[80] = {
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
};

static const uint8_t sl[80] = {
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
};

static const uint8_t sr[80] = {
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
};

static const uint32_t kl[5] = { 0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e };
static const uint32_t kr[5] = { 0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000 };

static uint32_t rmd_f(int j, uint32_t x, uint32_t y, uint32_t z)
{
    switch (j / 16) {
        case 0: return x ^ y ^ z;
        case 1: return (x & y) | (~x & z);
        case 2: return (x | ~y) ^ z;
        case 3: return (x & z) | (y & ~z);
        default: return x ^ (y | ~z);
    }
}

static uint32_t rol32(uint32_t x, unsigned n)
{
    return (x << n) | (x >> (32 - n));
}

static void ccrmd160_compress(ccdigest_state_t state, size_t nblocks, const void *in)
{
    const uint8_t *buf = in;
    uint32_t *h = ccdigest_u32(state);

    while (nblocks--) {
        uint32_t x[16];
        for (int i = 0; i < 16; i++) {
            x[i] = (uint32_t)buf[4 * i] | ((uint32_t)buf[4 * i + 1] << 8) |
                   ((uint32_t)buf[4 * i + 2] << 16) | ((uint32_t)buf[4 * i + 3] << 24);
        }

        uint32_t al = h[0], bl = h[1], cl = h[2], dl = h[3], el = h[4];
        uint32_t ar = al, br = bl, cr = cl, dr = dl, er = el;

        for (int j = 0; j < 80; j++) {
            uint32_t t = rol32(al + rmd_f(j, bl, cl, dl) + x[rl[j]] + kl[j / 16], sl[j]) + el;
            al = el; el = dl; dl = rol32(cl, 10); cl = bl; bl = t;

            // the right line runs the boolean functions in reverse order
            t = rol32(ar + rmd_f(79 - j, br, cr, dr) + x[rr[j]] + kr[j / 16], sr[j]) + er;
            ar = er; er = dr; dr = rol32(cr, 10); cr = br; br = t;
        }

        uint32_t t = h[1] + cl + dr;
        h[1] = h[2] + dl + er;
        h[2] = h[3] + el + ar;
        h[3] = h[4] + al + br;
        h[4] = h[0] + bl + cr;
        h[0] = t;

        buf += CCRMD160_BLOCK_SIZE;
    }
}

static const uint32_t ccrmd160_initial_state[5] = {
    0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
};

const struct ccdigest_info ccrmd160_ltc_di = {
    .output_size = CCRMD160_OUTPUT_SIZE,
    .state_size = CCRMD160_STATE_SIZE,
    .block_size = CCRMD160_BLOCK_SIZE,
    .initial_state = &ccrmd160_initial_state,
    .compress = &ccrmd160_compress,
    .final = &ccdigest_final_64le,
};
