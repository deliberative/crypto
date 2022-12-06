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

#include "../../../libsodium/src/libsodium/include/sodium/crypto_aead_chacha20poly1305.h"
#include "../../../libsodium/src/libsodium/include/sodium/crypto_kx.h"
#include "../../../libsodium/src/libsodium/include/sodium/crypto_sign_ed25519.h"
#include "../../../libsodium/src/libsodium/include/sodium/utils.h"

__attribute__((used)) int
key_decrypt_data(
    const int ENCRYPTED_LEN, const uint8_t encrypted_data[ENCRYPTED_LEN],
    const uint8_t key[crypto_kx_SESSIONKEYBYTES], const int ADDITIONAL_DATA_LEN,
    const uint8_t additional_data[ADDITIONAL_DATA_LEN],
    uint8_t data[ENCRYPTED_LEN - crypto_aead_chacha20poly1305_ietf_NPUBBYTES
                 - crypto_aead_chacha20poly1305_ietf_ABYTES])
{
  unsigned long long DATA_LEN = ENCRYPTED_LEN
                                - crypto_aead_chacha20poly1305_ietf_NPUBBYTES
                                - crypto_aead_chacha20poly1305_ietf_ABYTES;

  uint8_t *nonce = malloc(crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
  memcpy(nonce, encrypted_data, crypto_aead_chacha20poly1305_ietf_NPUBBYTES);

  int CIPHERTEXT_LEN
      = ENCRYPTED_LEN - crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
  uint8_t *ciphertext = malloc(CIPHERTEXT_LEN);
  memcpy(ciphertext,
         encrypted_data + crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
         CIPHERTEXT_LEN);

  int decrypted = crypto_aead_chacha20poly1305_ietf_decrypt(
      data, &DATA_LEN, NULL, ciphertext, CIPHERTEXT_LEN, additional_data,
      ADDITIONAL_DATA_LEN, nonce, key);

  free(ciphertext);
  free(nonce);

  if (decrypted == 0) return 0;

  return -1;
}
