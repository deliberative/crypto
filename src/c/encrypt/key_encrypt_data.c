// Copyright (C) 2022 Deliberative Technologies P.C.
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <stdint.h>
#include <string.h>

#include "./encrypt.h"

#include "../../../libsodium/src/libsodium/include/sodium/crypto_aead_chacha20poly1305.h"
#include "../../../libsodium/src/libsodium/include/sodium/crypto_kx.h"
#include "../../../libsodium/src/libsodium/include/sodium/crypto_scalarmult_curve25519.h"
#include "../../../libsodium/src/libsodium/include/sodium/crypto_sign_ed25519.h"
#include "../../../libsodium/src/libsodium/include/sodium/utils.h"

/* Returns (nonce || encrypted_data || auth tag) */
__attribute__((used)) int
key_encrypt_data(
    const int DATA_LEN, const uint8_t data[DATA_LEN],
    const uint8_t key[crypto_kx_SESSIONKEYBYTES], const int ADDITIONAL_DATA_LEN,
    const uint8_t additional_data[ADDITIONAL_DATA_LEN],
    uint8_t encrypted[crypto_aead_chacha20poly1305_ietf_NPUBBYTES + DATA_LEN
                      + crypto_aead_chacha20poly1305_ietf_ABYTES])
{
  unsigned long long CIPHERTEXT_LEN
      = DATA_LEN + crypto_aead_chacha20poly1305_ietf_ABYTES;
  uint8_t *ciphertext = sodium_malloc(CIPHERTEXT_LEN);

  uint8_t *nonce = malloc(crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
  calculate_nonce(nonce);

  crypto_aead_chacha20poly1305_ietf_encrypt(
      ciphertext, &CIPHERTEXT_LEN, data, DATA_LEN, additional_data,
      ADDITIONAL_DATA_LEN, NULL, nonce, key);

  memcpy(encrypted, nonce, crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
  free(nonce);

  memcpy(encrypted + crypto_aead_chacha20poly1305_ietf_NPUBBYTES, ciphertext,
         CIPHERTEXT_LEN);
  sodium_free(ciphertext);

  return 0;
}
