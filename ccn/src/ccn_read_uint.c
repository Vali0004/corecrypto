/*
 * Copyright (C) 2026, PureDarwin contributors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

// pd interim LLM-written code, experimental and not secure: unaudited, unfuzzed, no side-channel review

#include <corecrypto/ccn.h>
#include <corecrypto/cc_error.h>

// os2ip, rfc 8017 4.2
int ccn_read_uint(cc_size n, cc_unit *r, size_t data_nbytes, const uint8_t *data)
{
    while (data_nbytes && *data == 0) {
        data++;
        data_nbytes--;
    }
    if (data_nbytes > ccn_sizeof_n(n))
        return CCERR_PARAMETER;

    ccn_zero(n, r);
    for (size_t i = 0; i < data_nbytes; i++) {
        size_t k = data_nbytes - 1 - i;
        r[k / CC_UNIT_SIZE] |= (cc_unit)data[i] << (8 * (k % CC_UNIT_SIZE));
    }

    return CCERR_OK;
}

// i2osp, rfc 8017 4.1
int ccn_write_uint_padded(cc_size n, const cc_unit *s, size_t out_nbytes, uint8_t *out)
{
    if ((ccn_bitlen(n, s) + 7) / 8 > out_nbytes)
        return CCERR_PARAMETER;

    for (size_t i = 0; i < out_nbytes; i++) {
        size_t k = out_nbytes - 1 - i;
        size_t u = k / CC_UNIT_SIZE;
        out[i] = u < n ? (uint8_t)(s[u] >> (8 * (k % CC_UNIT_SIZE))) : 0;
    }

    return CCERR_OK;
}
