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
e2e_encrypt_data(
    const int DATA_LEN, const uint8_t data[DATA_LEN],
    const uint8_t public_key[crypto_sign_ed25519_PUBLICKEYBYTES],
    const uint8_t secret_key[crypto_sign_ed25519_SECRETKEYBYTES],
    const int ADDITIONAL_DATA_LEN,
    const uint8_t additional_data[ADDITIONAL_DATA_LEN],
    uint8_t encrypted[crypto_aead_chacha20poly1305_ietf_NPUBBYTES + DATA_LEN
                      + crypto_aead_chacha20poly1305_ietf_ABYTES])
{
  /* if (DATA_LEN > 2^12) return -2; // Encrypted data larger than expected
   */

  unsigned long long CIPHERTEXT_LEN
      = DATA_LEN + crypto_aead_chacha20poly1305_ietf_ABYTES;
  uint8_t *ciphertext = sodium_malloc(CIPHERTEXT_LEN);

  uint8_t *sender_x25519_pk = malloc(crypto_aead_chacha20poly1305_KEYBYTES);
  uint8_t *sender_x25519_sk = sodium_malloc(crypto_scalarmult_curve25519_BYTES);
  int converted_sk
      = crypto_sign_ed25519_sk_to_curve25519(sender_x25519_sk, secret_key);
  if (converted_sk != 0)
  {
    free(sender_x25519_pk);
    sodium_free(sender_x25519_sk);
    sodium_free(ciphertext);

    return -1;
  }

  crypto_scalarmult_curve25519_base(sender_x25519_pk, sender_x25519_sk);

  uint8_t *receiver_x25519_pk = malloc(crypto_scalarmult_curve25519_BYTES);
  int converted_pk
      = crypto_sign_ed25519_pk_to_curve25519(receiver_x25519_pk, public_key);
  if (converted_pk != 0)
  {
    free(receiver_x25519_pk);
    free(sender_x25519_pk);
    sodium_free(sender_x25519_sk);
    sodium_free(ciphertext);

    return -2;
  }

  uint8_t *server_tx = sodium_malloc(crypto_kx_SESSIONKEYBYTES);
  int created = crypto_kx_server_session_keys(
      NULL, server_tx, sender_x25519_pk, sender_x25519_sk, receiver_x25519_pk);
  free(sender_x25519_pk);
  free(receiver_x25519_pk);
  sodium_free(sender_x25519_sk);
  if (created != 0)
  {
    sodium_free(server_tx);
    sodium_free(ciphertext);

    return -3;
  }

  uint8_t *nonce = malloc(crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
  calculate_nonce(nonce);

  memcpy(encrypted, nonce, crypto_aead_chacha20poly1305_ietf_NPUBBYTES);

  crypto_aead_chacha20poly1305_ietf_encrypt(
      ciphertext, &CIPHERTEXT_LEN, data, DATA_LEN, additional_data,
      ADDITIONAL_DATA_LEN, NULL, nonce, server_tx);
  free(nonce);
  sodium_free(server_tx);

  memcpy(encrypted + crypto_aead_chacha20poly1305_ietf_NPUBBYTES, ciphertext,
         CIPHERTEXT_LEN);
  sodium_free(ciphertext);

  return 0;
}
