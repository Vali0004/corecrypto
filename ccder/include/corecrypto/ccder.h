/*
 * Copyright (C) 2026, PureDarwin contributors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

// pd interim LLM-written code, experimental and not secure: unaudited, unfuzzed, no side-channel review
// ccder.h - DER (ITU-T X.690) encoding and decoding for Security.framework's private corecrypto
//
// A ccder_tag keeps the class in its top two bits, the constructed flag in the next one and the tag number in the
// rest, so a tag is the class, the method and the number or'ed together (CCDER_PRIVATE | CCDER_SET). On the wire it
// is X.690's identifier octets.
//
// Encoders work backwards: der is the start of the output buffer, der_end the end of what is already encoded, and
// each returns the new start, or NULL when the buffer is too small or der_end is NULL, so calls nest. Decoders work
// forwards and return the first byte after what they read (the body, for a tag and length), or NULL.
#ifndef _CORECRYPTO_CCDER_H_
#define _CORECRYPTO_CCDER_H_

#include <stddef.h>
#include <stdint.h>
#include <corecrypto/ccn.h>
#include <ccder_blob.h>

#define CCDER_TAG_BITS          (sizeof(ccder_tag) * 8)
#define CCDER_CLASS_MASK        ((ccder_tag)3 << (CCDER_TAG_BITS - 2))
#define CCDER_UNIVERSAL         ((ccder_tag)0)
#define CCDER_APPLICATION       ((ccder_tag)1 << (CCDER_TAG_BITS - 2))
#define CCDER_CONTEXT_SPECIFIC  ((ccder_tag)2 << (CCDER_TAG_BITS - 2))
#define CCDER_PRIVATE           ((ccder_tag)3 << (CCDER_TAG_BITS - 2))
#define CCDER_METHOD_MASK       ((ccder_tag)1 << (CCDER_TAG_BITS - 3))
#define CCDER_PRIMITIVE         ((ccder_tag)0)
#define CCDER_CONSTRUCTED       CCDER_METHOD_MASK
#define CCDER_TAGNUM_MASK       (~(CCDER_CLASS_MASK | CCDER_METHOD_MASK))

#define CCDER_CONSTRUCTED_SET       (CCDER_SET | CCDER_CONSTRUCTED)
#define CCDER_CONSTRUCTED_SEQUENCE  (CCDER_SEQUENCE | CCDER_CONSTRUCTED)

#ifdef __cplusplus
extern "C" {
#endif

// sizes of encodings
size_t ccder_sizeof_tag(ccder_tag tag);
size_t ccder_sizeof_len(size_t len);
size_t ccder_sizeof(ccder_tag tag, size_t len);
size_t ccder_sizeof_implicit_raw_octet_string(ccder_tag tag, size_t len);
size_t ccder_sizeof_raw_octet_string(size_t len);
size_t ccder_sizeof_implicit_integer(ccder_tag tag, cc_size n, const cc_unit *s);
size_t ccder_sizeof_integer(cc_size n, const cc_unit *s);
size_t ccder_sizeof_implicit_uint64(ccder_tag tag, uint64_t value);
size_t ccder_sizeof_uint64(uint64_t value);

// encoders
uint8_t *ccder_encode_tag(ccder_tag tag, const uint8_t *der, uint8_t *der_end);
uint8_t *ccder_encode_len(size_t len, const uint8_t *der, uint8_t *der_end);
uint8_t *ccder_encode_tl(ccder_tag tag, size_t len, const uint8_t *der, uint8_t *der_end);
uint8_t *ccder_encode_body_nocopy(size_t size, const uint8_t *der, uint8_t *der_end);
uint8_t *ccder_encode_body(size_t size, const uint8_t *body, const uint8_t *der, uint8_t *der_end);
uint8_t *ccder_encode_constructed_tl(ccder_tag tag, const uint8_t *body_end, const uint8_t *der, uint8_t *der_end);
uint8_t *ccder_encode_implicit_integer(ccder_tag tag, cc_size n, const cc_unit *s, const uint8_t *der, uint8_t *der_end);
uint8_t *ccder_encode_integer(cc_size n, const cc_unit *s, const uint8_t *der, uint8_t *der_end);
uint8_t *ccder_encode_implicit_uint64(ccder_tag tag, uint64_t value, const uint8_t *der, uint8_t *der_end);
uint8_t *ccder_encode_uint64(uint64_t value, const uint8_t *der, uint8_t *der_end);
uint8_t *ccder_encode_implicit_raw_octet_string(ccder_tag tag, size_t len, const uint8_t *s, const uint8_t *der,
    uint8_t *der_end);
uint8_t *ccder_encode_raw_octet_string(size_t len, const uint8_t *s, const uint8_t *der, uint8_t *der_end);

// decoders
const uint8_t *ccder_decode_tag(ccder_tag *tagp, const uint8_t *der, const uint8_t *der_end);
const uint8_t *ccder_decode_len(size_t *lenp, const uint8_t *der, const uint8_t *der_end);
const uint8_t *ccder_decode_tl(ccder_tag expected_tag, size_t *lenp, const uint8_t *der, const uint8_t *der_end);
const uint8_t *ccder_decode_constructed_tl(ccder_tag expected_tag, const uint8_t **body_end, const uint8_t *der,
    const uint8_t *der_end);
const uint8_t *ccder_decode_sequence_tl(const uint8_t **body_end, const uint8_t *der, const uint8_t *der_end);
// an INTEGER's size in units (0 when it is not a non-negative INTEGER), the INTEGER into n units, and into a uint64_t
cc_size ccder_decode_uint_n(const uint8_t *der, const uint8_t *der_end);
const uint8_t *ccder_decode_uint(cc_size n, cc_unit *r, const uint8_t *der, const uint8_t *der_end);
const uint8_t *ccder_decode_uint64(uint64_t *r, const uint8_t *der, const uint8_t *der_end);
// SEQUENCE { INTEGER r, INTEGER s }, an ECDSA or DSA signature
const uint8_t *ccder_decode_seqii(cc_size n, cc_unit *r, cc_unit *s, const uint8_t *der, const uint8_t *der_end);

#ifdef __cplusplus
}
#endif

#endif
