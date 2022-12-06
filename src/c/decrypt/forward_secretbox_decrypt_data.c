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
#include "../../../libsodium/src/libsodium/include/sodium/crypto_scalarmult_curve25519.h"
#include "../../../libsodium/src/libsodium/include/sodium/crypto_sign_ed25519.h"
#include "../../../libsodium/src/libsodium/include/sodium/utils.h"

__attribute__((used)) int
forward_secretbox_decrypt_data(
    const int ENCRYPTED_LEN, const uint8_t encrypted_data[ENCRYPTED_LEN],
    const uint8_t secret_key[crypto_sign_ed25519_SECRETKEYBYTES],
    const int ADDITIONAL_DATA_LEN,
    const uint8_t additional_data[ADDITIONAL_DATA_LEN],
    uint8_t data[ENCRYPTED_LEN - crypto_scalarmult_curve25519_BYTES
                 - crypto_aead_chacha20poly1305_ietf_NPUBBYTES
                 - crypto_aead_chacha20poly1305_ietf_ABYTES])
{
  int EPHEMERAL_NONCE_LEN = crypto_scalarmult_curve25519_BYTES
                            + crypto_aead_chacha20poly1305_ietf_NPUBBYTES;

  unsigned long long DATA_LEN = ENCRYPTED_LEN - EPHEMERAL_NONCE_LEN
                                - crypto_aead_chacha20poly1305_ietf_ABYTES
                                - crypto_sign_ed25519_BYTES;

  uint8_t *ephemeral_x25519_pk = malloc(crypto_scalarmult_curve25519_BYTES);
  memcpy(ephemeral_x25519_pk, encrypted_data,
         crypto_scalarmult_curve25519_BYTES);

  uint8_t *nonce = malloc(crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
  memcpy(nonce, encrypted_data + crypto_scalarmult_curve25519_BYTES,
         crypto_aead_chacha20poly1305_ietf_NPUBBYTES);

  uint8_t *x25519_pk = malloc(crypto_aead_chacha20poly1305_KEYBYTES);
  uint8_t *x25519_sk = sodium_malloc(crypto_scalarmult_curve25519_BYTES);
  crypto_sign_ed25519_sk_to_curve25519(x25519_sk, secret_key);
  crypto_scalarmult_curve25519_base(x25519_pk, x25519_sk);

  uint8_t *client_rx = sodium_malloc(crypto_kx_SESSIONKEYBYTES);
  int created = crypto_kx_client_session_keys(client_rx, NULL, x25519_pk,
                                              x25519_sk, ephemeral_x25519_pk);
  free(x25519_pk);
  sodium_free(x25519_sk);
  free(ephemeral_x25519_pk);
  if (created != 0)
  {
    free(nonce);
    sodium_free(client_rx);

    return -1;
  }

  int CIPHERTEXT_LEN = ENCRYPTED_LEN - EPHEMERAL_NONCE_LEN;
  uint8_t *ciphertext = malloc(CIPHERTEXT_LEN);
  memcpy(ciphertext, encrypted_data + EPHEMERAL_NONCE_LEN, CIPHERTEXT_LEN);

  int decrypted = crypto_aead_chacha20poly1305_ietf_decrypt(
      data, &DATA_LEN, NULL, ciphertext, CIPHERTEXT_LEN, additional_data,
      ADDITIONAL_DATA_LEN, nonce, client_rx);

  free(ciphertext);
  sodium_free(client_rx);
  free(nonce);

  if (decrypted == 0) return 0;

  return -2;
}
