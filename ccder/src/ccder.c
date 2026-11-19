/*
 * Copyright (C) 2026, PureDarwin contributors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

// pd interim LLM-written code, experimental and not secure: unaudited, unfuzzed, no side-channel review
// ccder.c - DER encoding and decoding, written from ITU-T X.690 (08/2015): identifier octets 8.1.2, length octets
// 8.1.3 (definite form only, as DER requires, 10.1), INTEGER 8.3 (two's complement, minimal octets)
#include <string.h>
#include <corecrypto/ccder.h>

// the tag number and the first identifier octet's class and method bits
#define TAGNUM(t)   ((t) & CCDER_TAGNUM_MASK)
#define CLASSBITS(t) ((uint8_t)(((t) & CCDER_CLASS_MASK) >> (CCDER_TAG_BITS - 8)))
#define METHODBIT(t) ((uint8_t)(((t) & CCDER_METHOD_MASK) >> (CCDER_TAG_BITS - 8)))

size_t ccder_sizeof_tag(ccder_tag tag)
{
    ccder_tag num = TAGNUM(tag);
    size_t size = 1;

    // numbers from 31 on take the high-tag-number form, 7 bits per octet after the first (8.1.2.4)
    if (num >= 0x1f) {
        do {
            size++;
            num >>= 7;
        } while (num != 0);
    }
    return size;
}

size_t ccder_sizeof_len(size_t len)
{
    size_t size = 1;

    // the long form is one octet giving the count, then the length big-endian (8.1.3.5)
    if (len >= 0x80) {
        do {
            size++;
            len >>= 8;
        } while (len != 0);
    }
    return size;
}

size_t ccder_sizeof(ccder_tag tag, size_t len)
{
    return ccder_sizeof_tag(tag) + ccder_sizeof_len(len) + len;
}

size_t ccder_sizeof_implicit_raw_octet_string(ccder_tag tag, size_t len)
{
    return ccder_sizeof(tag, len);
}

size_t ccder_sizeof_raw_octet_string(size_t len)
{
    return ccder_sizeof(CCDER_OCTET_STRING, len);
}

// the octets of a non-negative number of n units, most significant first: how many there are, with the leading
// zero octet DER needs when the top bit of the first one is set
static size_t integer_octets(cc_size n, const cc_unit *s)
{
    size_t len = n * sizeof(cc_unit);
    size_t i;

    for (i = len; i > 0; i--) {
        size_t unit = (i - 1) / sizeof(cc_unit), shift = ((i - 1) % sizeof(cc_unit)) * 8;
        uint8_t b = (uint8_t)(s[unit] >> shift);
        if (b != 0)
            return (b & 0x80) ? i + 1 : i;
    }
    return 1;   // zero is one octet
}

static uint8_t integer_octet(cc_size n, const cc_unit *s, size_t i)
{
    size_t unit = i / sizeof(cc_unit);

    return unit < n ? (uint8_t)(s[unit] >> ((i % sizeof(cc_unit)) * 8)) : 0;
}

size_t ccder_sizeof_implicit_integer(ccder_tag tag, cc_size n, const cc_unit *s)
{
    return ccder_sizeof(tag, integer_octets(n, s));
}

size_t ccder_sizeof_integer(cc_size n, const cc_unit *s)
{
    return ccder_sizeof_implicit_integer(CCDER_INTEGER, n, s);
}

static size_t uint64_octets(uint64_t value)
{
    size_t len = 1;

    while (len < 8 && (value >> (len * 8)) != 0)
        len++;
    return (value >> (len * 8 - 1)) & 1 ? len + 1 : len;
}

size_t ccder_sizeof_implicit_uint64(ccder_tag tag, uint64_t value)
{
    return ccder_sizeof(tag, uint64_octets(value));
}

size_t ccder_sizeof_uint64(uint64_t value)
{
    return ccder_sizeof_implicit_uint64(CCDER_INTEGER, value);
}

// room for size octets before der_end, and the new start
static uint8_t *take(size_t size, const uint8_t *der, uint8_t *der_end)
{
    if (der == NULL || der_end == NULL || der_end < der || (size_t)(der_end - der) < size)
        return NULL;
    return der_end - size;
}

uint8_t *ccder_encode_tag(ccder_tag tag, const uint8_t *der, uint8_t *der_end)
{
    ccder_tag num = TAGNUM(tag);
    size_t size = ccder_sizeof_tag(tag);
    uint8_t *p = take(size, der, der_end);
    size_t i;

    if (p == NULL)
        return NULL;
    if (size == 1) {
        p[0] = CLASSBITS(tag) | METHODBIT(tag) | (uint8_t)num;
        return p;
    }
    p[0] = CLASSBITS(tag) | METHODBIT(tag) | 0x1f;
    // base 128, most significant group first, every octet but the last with bit 8 set
    for (i = size - 1; i >= 1; i--) {
        p[i] = (uint8_t)(num & 0x7f) | (i == size - 1 ? 0 : 0x80);
        num >>= 7;
    }
    return p;
}

uint8_t *ccder_encode_len(size_t len, const uint8_t *der, uint8_t *der_end)
{
    size_t size = ccder_sizeof_len(len);
    uint8_t *p = take(size, der, der_end);
    size_t i;

    if (p == NULL)
        return NULL;
    if (size == 1) {
        p[0] = (uint8_t)len;
        return p;
    }
    p[0] = 0x80 | (uint8_t)(size - 1);
    for (i = size - 1; i >= 1; i--) {
        p[i] = (uint8_t)len;
        len >>= 8;
    }
    return p;
}

uint8_t *ccder_encode_tl(ccder_tag tag, size_t len, const uint8_t *der, uint8_t *der_end)
{
    return ccder_encode_tag(tag, der, ccder_encode_len(len, der, der_end));
}

uint8_t *ccder_encode_body_nocopy(size_t size, const uint8_t *der, uint8_t *der_end)
{
    return take(size, der, der_end);
}

uint8_t *ccder_encode_body(size_t size, const uint8_t *body, const uint8_t *der, uint8_t *der_end)
{
    uint8_t *p = take(size, der, der_end);

    if (p != NULL && size != 0)
        memmove(p, body, size);
    return p;
}

uint8_t *ccder_encode_constructed_tl(ccder_tag tag, const uint8_t *body_end, const uint8_t *der, uint8_t *der_end)
{
    // the body is already encoded, from der_end to body_end
    if (der_end == NULL || body_end == NULL || body_end < der_end)
        return NULL;
    return ccder_encode_tl(tag, (size_t)(body_end - der_end), der, der_end);
}

uint8_t *ccder_encode_implicit_integer(ccder_tag tag, cc_size n, const cc_unit *s, const uint8_t *der,
    uint8_t *der_end)
{
    size_t len = integer_octets(n, s);
    uint8_t *p = take(len, der, der_end);
    size_t i;

    if (p == NULL)
        return NULL;
    // the octet at p[k] is the number's octet len - 1 - k, the leading zero one included
    for (i = 0; i < len; i++)
        p[i] = integer_octet(n, s, len - 1 - i);
    return ccder_encode_tl(tag, len, der, p);
}

uint8_t *ccder_encode_integer(cc_size n, const cc_unit *s, const uint8_t *der, uint8_t *der_end)
{
    return ccder_encode_implicit_integer(CCDER_INTEGER, n, s, der, der_end);
}

uint8_t *ccder_encode_implicit_uint64(ccder_tag tag, uint64_t value, const uint8_t *der, uint8_t *der_end)
{
    size_t len = uint64_octets(value);
    uint8_t *p = take(len, der, der_end);
    size_t i;

    if (p == NULL)
        return NULL;
    for (i = 0; i < len; i++) {
        size_t shift = (len - 1 - i) * 8;
        p[i] = shift < 64 ? (uint8_t)(value >> shift) : 0;
    }
    return ccder_encode_tl(tag, len, der, p);
}

uint8_t *ccder_encode_uint64(uint64_t value, const uint8_t *der, uint8_t *der_end)
{
    return ccder_encode_implicit_uint64(CCDER_INTEGER, value, der, der_end);
}

uint8_t *ccder_encode_implicit_raw_octet_string(ccder_tag tag, size_t len, const uint8_t *s, const uint8_t *der,
    uint8_t *der_end)
{
    return ccder_encode_tl(tag, len, der, ccder_encode_body(len, s, der, der_end));
}

uint8_t *ccder_encode_raw_octet_string(size_t len, const uint8_t *s, const uint8_t *der, uint8_t *der_end)
{
    return ccder_encode_implicit_raw_octet_string(CCDER_OCTET_STRING, len, s, der, der_end);
}

const uint8_t *ccder_decode_tag(ccder_tag *tagp, const uint8_t *der, const uint8_t *der_end)
{
    ccder_tag tag, num;
    uint8_t first;

    if (der == NULL || der_end == NULL || der >= der_end)
        return NULL;
    first = *der++;
    tag = ((ccder_tag)(first & 0xc0) << (CCDER_TAG_BITS - 8)) | ((ccder_tag)(first & 0x20) << (CCDER_TAG_BITS - 8));
    num = first & 0x1f;
    if (num == 0x1f) {
        // high-tag-number form: no leading 0x80 octet (8.1.2.4.2 c), and the number has to fit
        num = 0;
        if (der < der_end && *der == 0x80)
            return NULL;
        do {
            if (der >= der_end || (num >> (CCDER_TAG_BITS - 3 - 7)) != 0)
                return NULL;
            num = (num << 7) | (*der & 0x7f);
        } while (*der++ & 0x80);
    }
    *tagp = tag | num;
    return der;
}

const uint8_t *ccder_decode_len(size_t *lenp, const uint8_t *der, const uint8_t *der_end)
{
    size_t len, count;

    if (der == NULL || der_end == NULL || der >= der_end)
        return NULL;
    len = *der++;
    if (len & 0x80) {
        // 0x80 is the indefinite form, which DER does not allow, and the count has to fit a size_t
        count = len & 0x7f;
        if (count == 0 || count > sizeof(size_t) || (size_t)(der_end - der) < count)
            return NULL;
        len = 0;
        while (count-- != 0)
            len = (len << 8) | *der++;
    }
    if ((size_t)(der_end - der) < len)
        return NULL;
    *lenp = len;
    return der;
}

const uint8_t *ccder_decode_tl(ccder_tag expected_tag, size_t *lenp, const uint8_t *der, const uint8_t *der_end)
{
    ccder_tag tag;

    der = ccder_decode_tag(&tag, der, der_end);
    if (der == NULL || tag != expected_tag)
        return NULL;
    return ccder_decode_len(lenp, der, der_end);
}

const uint8_t *ccder_decode_constructed_tl(ccder_tag expected_tag, const uint8_t **body_end, const uint8_t *der,
    const uint8_t *der_end)
{
    size_t len;

    der = ccder_decode_tl(expected_tag, &len, der, der_end);
    if (der != NULL)
        *body_end = der + len;
    return der;
}

const uint8_t *ccder_decode_sequence_tl(const uint8_t **body_end, const uint8_t *der, const uint8_t *der_end)
{
    return ccder_decode_constructed_tl(CCDER_CONSTRUCTED_SEQUENCE, body_end, der, der_end);
}

// a non-negative INTEGER's value octets without the sign octet, or NULL
static const uint8_t *uint_body(size_t *lenp, const uint8_t *der, const uint8_t *der_end)
{
    size_t len;
    const uint8_t *body = ccder_decode_tl(CCDER_INTEGER, &len, der, der_end);

    if (body == NULL || len == 0 || (body[0] & 0x80) != 0)
        return NULL;
    // a leading zero is only there for the sign of the next octet (8.3.2)
    if (len > 1 && body[0] == 0) {
        if ((body[1] & 0x80) == 0)
            return NULL;
        body++;
        len--;
    }
    *lenp = len;
    return body;
}

cc_size ccder_decode_uint_n(const uint8_t *der, const uint8_t *der_end)
{
    size_t len;
    const uint8_t *body = uint_body(&len, der, der_end);

    if (body == NULL)
        return 0;
    return (len + sizeof(cc_unit) - 1) / sizeof(cc_unit);
}

const uint8_t *ccder_decode_uint(cc_size n, cc_unit *r, const uint8_t *der, const uint8_t *der_end)
{
    size_t len, i;
    const uint8_t *body = uint_body(&len, der, der_end);

    if (body == NULL || len > n * sizeof(cc_unit))
        return NULL;
    memset(r, 0, n * sizeof(cc_unit));
    for (i = 0; i < len; i++) {
        size_t octet = len - 1 - i;
        r[octet / sizeof(cc_unit)] |= (cc_unit)body[i] << ((octet % sizeof(cc_unit)) * 8);
    }
    return body + len;
}

const uint8_t *ccder_decode_uint64(uint64_t *r, const uint8_t *der, const uint8_t *der_end)
{
    size_t len, i;
    uint64_t value = 0;
    const uint8_t *body = uint_body(&len, der, der_end);

    if (body == NULL || len > 8)
        return NULL;
    for (i = 0; i < len; i++)
        value = (value << 8) | body[i];
    *r = value;
    return body + len;
}

const uint8_t *ccder_decode_seqii(cc_size n, cc_unit *r, cc_unit *s, const uint8_t *der, const uint8_t *der_end)
{
    const uint8_t *body_end;

    der = ccder_decode_sequence_tl(&body_end, der, der_end);
    der = ccder_decode_uint(n, r, der, body_end);
    der = ccder_decode_uint(n, s, der, body_end);
    return der == body_end ? der : NULL;
}
