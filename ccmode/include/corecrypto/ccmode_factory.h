/*
 * Copyright (C) 2026, Samuel Zormeister.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef __CORECRYPTO_CCMODE_FACTORY_H__
#define __CORECRYPTO_CCMODE_FACTORY_H__

#include <corecrypto/ccmode_impl.h>

CC_BEGIN_DECLS

/*!
 * @function ccmode_factory_cbc_decrypt
 * Initialises a ccmode_cbc structure using an ECB implementation, in the decryption mode.
 *
 * @param       cbc
 *              The structure to initialise
 *
 * @param       ecb
 *              The underlying ECB cipher to use.
 */
void ccmode_factory_cbc_decrypt(struct ccmode_cbc *cbc,
                                const struct ccmode_ecb *ecb);

/*!
 * @function ccmode_factory_cbc_encrypt
 * Initialises a ccmode_cbc structure using an ECB implementation, in the encryption mode.
 *
 * @param       cbc
 *              The structure to initialise
 *
 * @param       ecb
 *              The underlying ECB cipher to use.
 */
void ccmode_factory_cbc_encrypt(struct ccmode_cbc *cbc,
                                const struct ccmode_ecb *ecb);

/*!
 * @function ccmode_factory_ctr_crypt
 * Initialises a ccmode_ctr structure using an ECB implementation.
 *
 * @param       cbc
 *              The structure to initialise
 *
 * @param       ecb
 *              The underlying ECB cipher to use.
 */
void ccmode_factory_ctr_crypt(struct ccmode_ctr *cbc,
                              const struct ccmode_ecb *ecb);


/*!
 * @function ccmode_factory_xts_decrypt
 * Initialises a ccmode_xts structure using an ECB implementation, in the decryption mode.
 *
 * @param       xts
 *              The structure to initialise
 *
 * @param       ecb
 *              The underlying ECB cipher to use.
 */
void ccmode_factory_xts_decrypt(struct ccmode_xts *xts,
                                const struct ccmode_ecb *ecb,
                                const struct ccmode_ecb *ecb_encrypt);

/*!
 * @function ccmode_factory_xts_encrypt
 * Initialises a ccmode_xts structure using an ECB implementation, in the encryption mode.
 *
 * @param       xts
 *              The structure to initialise
 *
 * @param       ecb
 *              The underlying ECB cipher to use.
 */
void ccmode_factory_xts_encrypt(struct ccmode_xts *xts,
                                const struct ccmode_ecb *ecb,
                                const struct ccmode_ecb *ecb_encrypt);


// matches struct _ccmode_ccm_nonce in the shipped interface headers (CommonCrypto reads mac_size)
struct _ccmode_ccm_nonce {
    unsigned char A_i[16];
    unsigned char B_i[16];
    unsigned char MAC[16];
    unsigned char buf[16];

    uint32_t mode;
    uint32_t buflen;
    uint32_t b_i_len;

    size_t nonce_size;
    size_t mac_size;
};

// factories for the modes built over an encrypting ecb
void ccmode_factory_cfb_encrypt(struct ccmode_cfb *cfb, const struct ccmode_ecb *ecb);
void ccmode_factory_cfb_decrypt(struct ccmode_cfb *cfb, const struct ccmode_ecb *ecb);
void ccmode_factory_cfb8_encrypt(struct ccmode_cfb8 *cfb8, const struct ccmode_ecb *ecb);
void ccmode_factory_cfb8_decrypt(struct ccmode_cfb8 *cfb8, const struct ccmode_ecb *ecb);
void ccmode_factory_ofb_crypt(struct ccmode_ofb *ofb, const struct ccmode_ecb *ecb);
void ccmode_factory_gcm_encrypt(struct ccmode_gcm *gcm, const struct ccmode_ecb *ecb_encrypt);
void ccmode_factory_gcm_decrypt(struct ccmode_gcm *gcm, const struct ccmode_ecb *ecb_encrypt);
void ccmode_factory_ccm_encrypt(struct ccmode_ccm *ccm, const struct ccmode_ecb *ecb_encrypt);
void ccmode_factory_ccm_decrypt(struct ccmode_ccm *ccm, const struct ccmode_ecb *ecb_encrypt);

CC_END_DECLS

#endif /* __CORECRYPTO_CCMODE_FACTORY_H__ */
