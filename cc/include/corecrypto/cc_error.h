/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CC_ERROR_H__
#define __CORECRYPTO_CC_ERROR_H__

/* Likely going to back the APIs with an integer return code. */
typedef int cc_error_t;

/* Error result codes */
#define CCERR_OK                0
#define CCERR_INTERNAL          -1
#define CCERR_INTEGRITY         -2
#define CCERR_DEVICE            -3
#define CCERR_INTERRUPTS        -4
#define CCERR_CRYPTO_CONFIG     -5
#define CCERR_PERMS             -6
#define CCERR_PARAMETER         -7
#define CCERR_MEMORY            -8
#define CCERR_FILEDESC          -9
#define CCERR_OUT_OF_ENTROPY    -10
#define CCERR_ATFORK            -11
#define CCERR_OVERFLOW          -12

typedef int ccdrbg_status_t;

#define CCDRBG_STATUS_OK            CCERR_OK
#define CCDRBG_STATUS_ERROR         -61
#define CCDRBG_STATUS_NEED_RESEED   -62
#define CCDRBG_STATUS_PARAM_ERROR   -63
#define CCDRBG_STATUS_ABORT         -64

#define CCKPRNG_NEED_ENTROPY            -65
#define CCKPRNG_ABORT                   -66
#define CCMODE_INVALID_INPUT            -67
#define CCMODE_INVALID_CALL_SEQUENCE    -68
#define CCMODE_INTEGRITY_FAILURE        -69
#define CCMODE_NOT_SUPPORTED            -70
#define CCMODE_INTERNAL_ERROR           -71
#define CCPOST_GENERIC_FAILURE          -72
#define CCPOST_LIBRARY_ERROR            -73
#define CCPOST_INTEGRITY_ERROR          -74
#define CCPOST_KAT_FAILURE              -75


#endif /* __CORECRYPTO_CC_ERROR_H__ */
