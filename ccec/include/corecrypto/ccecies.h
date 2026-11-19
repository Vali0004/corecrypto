/*
 * Copyright (C) 2026, PureDarwin contributors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

// pd interim LLM-written code, experimental and not secure: unaudited, unfuzzed, no side-channel review
// ccecies.h - ECIES with AES-GCM (SEC 1 5.1), not implemented yet: the setup is recorded, the operations return
// CCEC_PD_UNSUPPORTED
#ifndef _CORECRYPTO_CCECIES_H_
#define _CORECRYPTO_CCECIES_H_

#include <corecrypto/ccec.h>

#define ECIES_EPH_PUBKEY_IN_SHAREDINFO1     0x01
#define ECIES_EXPORT_PUB_STANDARD           0x02
#define ECIES_EXPORT_PUB_COMPACT            0x04
#define ECIES_LEGACY_IV                     0x08

struct ccmode_gcm;
struct ccecies_gcm {
    const struct ccdigest_info *di;
    struct ccrng_state *rng;
    const struct ccmode_gcm *gcm;
    uint32_t key_length;
    uint32_t mac_length;
    uint32_t options;
};
typedef struct ccecies_gcm *ccecies_gcm_t;

#ifdef __cplusplus
extern "C" {
#endif

void ccecies_encrypt_gcm_setup(ccecies_gcm_t ecies, const struct ccdigest_info *di, struct ccrng_state *rng,
    const struct ccmode_gcm *aes_gcm_enc, uint32_t cipher_key_size, uint32_t mac_tag_size, uint32_t options);
void ccecies_decrypt_gcm_setup(ccecies_gcm_t ecies, const struct ccdigest_info *di,
    const struct ccmode_gcm *aes_gcm_dec, uint32_t cipher_key_size, uint32_t mac_tag_size, uint32_t options);
size_t ccecies_encrypt_gcm_ciphertext_size(ccec_pub_ctx_t public_key, ccecies_gcm_t ecies, size_t plaintext_len);
size_t ccecies_decrypt_gcm_plaintext_size(ccec_full_ctx_t full_key, ccecies_gcm_t ecies, size_t ciphertext_len);
int ccecies_encrypt_gcm(ccec_pub_ctx_t public_key, const ccecies_gcm_t ecies, size_t plaintext_len,
    const uint8_t *plaintext, size_t sharedinfo1_byte_len, const void *sharedinfo_1, size_t sharedinfo2_byte_len,
    const void *sharedinfo_2, size_t *encrypted_blob_len, uint8_t *encrypted_blob);
int ccecies_decrypt_gcm(ccec_full_ctx_t full_key, const ccecies_gcm_t ecies, size_t encrypted_blob_len,
    const uint8_t *encrypted_blob, size_t sharedinfo1_byte_len, const void *sharedinfo_1,
    size_t sharedinfo2_byte_len, const void *sharedinfo_2, size_t *plaintext_len, uint8_t *plaintext);

#ifdef __cplusplus
}
#endif

#endif
