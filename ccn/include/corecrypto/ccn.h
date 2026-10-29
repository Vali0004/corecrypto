/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CCN_H__
#define __CORECRYPTO_CCN_H__

#include <corecrypto/cc.h>
#include <corecrypto/cc_memory.h>

CC_BEGIN_DECLS

/*
 * If we really want to be technical here, ccn is a component of yet another arbitrary precision integer implementation.
 *
 * A "unit" translates to the common term of "limb", and "n" is just the limb count.
 *
 * Anyways, said units are arranged in a least-significant to most significant in order.
 *
 * The difference is that ccn operates under the assumption that the number of units is known and expected at any given time, without
 * the need for automatic growth of a memory pool. That's what ccz is for.
 */

#define ccn_sizeof_n(n)         (sizeof(cc_unit) * (n))
#define ccn_nof(bits)           (((bits) + CC_UNIT_BITS - 1) >> CC_LOG2_BITS_PER_UNIT)
#define ccn_sizeof(bits)        (ccn_sizeof_n(ccn_nof(bits)))
#define ccn_nof_size(size)      (((size) + CC_UNIT_SIZE - 1) / CC_UNIT_SIZE)
#define ccn_nof_sizeof(type)    ccn_nof_size(sizeof(type))
#define ccn_bitsof_n(n)         ((n) * CC_UNIT_BITS)
#define ccn_bitsof_size(size)   ((size) * 8)
#define ccn_sizeof_size(size)   ccn_sizeof_n(ccn_nof_size(size))

#define ccn_bit(ccn, k) ({                                                          \
        __typeof__(k) _k = (k);                                                     \
        1 & ((ccn)[_k >> CC_LOG2_BITS_PER_UNIT] >> (_k & (CC_UNIT_BITS - 1)));      \
    })

#define ccn_set_bit(ccn, k, v) ({                                                               \
    __typeof__(k) _k = (k);                                                                     \
    if (v)                                                                                      \
        (ccn)[ _k >> CC_LOG2_BITS_PER_UNIT] |= CC_UNIT_C(1) << (_k & (CC_UNIT_BITS - 1));       \
    else                                                                                        \
        (ccn)[ _k >> CC_LOG2_BITS_PER_UNIT] &= ~(CC_UNIT_C(1) << (_k & (CC_UNIT_BITS - 1)));    \
    })

/* Basic operations */

/*
 */

/*!
 * @function ccn_add
 *
 * @param   n   The number of units in both s and t
 *
 * @param   r   The result of the operation
 *
 * @param   s   First operand
 *
 * @param   t   Second operand
 *
 * @result  The returned cc_unit is the carry from the last add of cc_units
 */
CC_EXPORT
cc_unit ccn_add(cc_size n, cc_unit *r, const cc_unit *s, const cc_unit *t);

/*!
 * @function ccn_sub
 *
 * @param   n   The number of units in both s and t
 *
 * @param   r   The result of the operation
 *
 * @param   s   First operand
 *
 * @param   t   Second operand
 *
 * @result  The returned cc_unit is the borrow from the last add of cc_units
 */
CC_EXPORT
cc_unit ccn_sub(cc_size n, cc_unit *r, const cc_unit *s, const cc_unit *t);

// pd: the rest is what rsa public-key verification needs, variable time

// compares s and t, returns -1, 0 or 1
CC_EXPORT
int ccn_cmp(cc_size n, const cc_unit *s, const cc_unit *t);

// number of units up to and including the top nonzero one
CC_EXPORT
cc_size ccn_n(cc_size n, const cc_unit *s);

// bit length of s, 0 for zero
CC_EXPORT
size_t ccn_bitlen(cc_size n, const cc_unit *s);

CC_EXPORT
void ccn_zero(cc_size n, cc_unit *r);

CC_EXPORT
void ccn_set(cc_size n, cc_unit *r, const cc_unit *s);

// big-endian bytes to n units, CCERR_PARAMETER when the value does not fit
CC_EXPORT
int ccn_read_uint(cc_size n, cc_unit *r, size_t data_nbytes, const uint8_t *data);

// n units to exactly out_nbytes big-endian bytes, CCERR_PARAMETER when the value does not fit
CC_EXPORT
int ccn_write_uint_padded(cc_size n, const cc_unit *s, size_t out_nbytes, uint8_t *out);

CC_END_DECLS

#endif /* __CORECRYPTO_CCN_H__  */
