// Copyright (C) 2023 Deliberative Technologies P.C.
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

#include "../../../libsodium/src/libsodium/include/sodium/utils.h"

#include "../../../libsodium/src/libsodium/include/sodium/crypto_aead_chacha20poly1305.h"
#include "../../../libsodium/src/libsodium/include/sodium/crypto_kx.h"
#include "../../../libsodium/src/libsodium/include/sodium/crypto_scalarmult_curve25519.h"
#include "../../../libsodium/src/libsodium/include/sodium/crypto_sign_ed25519.h"

__attribute__((used)) int
e2e_decrypt_data(
    const int ENCRYPTED_LEN, const uint8_t encrypted_data[ENCRYPTED_LEN],
    const uint8_t public_key[crypto_sign_ed25519_PUBLICKEYBYTES],
    const uint8_t secret_key[crypto_sign_ed25519_SECRETKEYBYTES],
    const int ADDITIONAL_DATA_LEN,
    const uint8_t additional_data[ADDITIONAL_DATA_LEN],
    uint8_t data[ENCRYPTED_LEN - crypto_aead_chacha20poly1305_ietf_NPUBBYTES
                 - crypto_aead_chacha20poly1305_ietf_ABYTES])
{
  unsigned long long DATA_LEN = ENCRYPTED_LEN
                                - crypto_aead_chacha20poly1305_ietf_NPUBBYTES
                                - crypto_aead_chacha20poly1305_ietf_ABYTES;

  uint8_t *sender_x25519_pk
      = malloc(sizeof(uint8_t[crypto_scalarmult_curve25519_BYTES]));
  if (sender_x25519_pk == NULL) return -1;

  int converted_pk
      = crypto_sign_ed25519_pk_to_curve25519(sender_x25519_pk, public_key);
  if (converted_pk != 0)
  {
    free(sender_x25519_pk);

    return -2;
  }

  uint8_t *nonce
      = malloc(sizeof(uint8_t[crypto_aead_chacha20poly1305_ietf_NPUBBYTES]));
  if (nonce == NULL)
  {
    free(sender_x25519_pk);

    return -3;
  }

  memcpy(nonce, encrypted_data, crypto_aead_chacha20poly1305_ietf_NPUBBYTES);

  uint8_t *receiver_x25519_pk
      = malloc(sizeof(uint8_t[crypto_aead_chacha20poly1305_KEYBYTES]));
  if (receiver_x25519_pk == NULL)
  {
    free(sender_x25519_pk);
    free(nonce);

    return -4;
  }

  uint8_t *receiver_x25519_sk
      = sodium_malloc(sizeof(uint8_t[crypto_scalarmult_curve25519_BYTES]));
  if (receiver_x25519_sk == NULL)
  {
    free(sender_x25519_pk);
    free(nonce);
    free(receiver_x25519_pk);

    return -5;
  }

  crypto_sign_ed25519_sk_to_curve25519(receiver_x25519_sk, secret_key);
  crypto_scalarmult_curve25519_base(receiver_x25519_pk, receiver_x25519_sk);

  uint8_t *client_rx
      = sodium_malloc(sizeof(uint8_t[crypto_kx_SESSIONKEYBYTES]));
  if (client_rx == NULL)
  {
    free(sender_x25519_pk);
    free(nonce);
    free(receiver_x25519_pk);
    sodium_free(receiver_x25519_sk);

    return -6;
  }

  int created
      = crypto_kx_client_session_keys(client_rx, NULL, receiver_x25519_pk,
                                      receiver_x25519_sk, sender_x25519_pk);
  free(receiver_x25519_pk);
  sodium_free(receiver_x25519_sk);
  free(sender_x25519_pk);
  if (created != 0)
  {
    free(nonce);
    sodium_free(client_rx);

    return -7;
  }

  int CIPHERTEXT_LEN
      = ENCRYPTED_LEN - crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
  uint8_t *ciphertext = malloc(sizeof(uint8_t[CIPHERTEXT_LEN]));
  if (ciphertext == NULL)
  {
    free(nonce);
    sodium_free(client_rx);

    return -8;
  }

  memcpy(ciphertext,
         encrypted_data + crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
         CIPHERTEXT_LEN);

  int decrypted = crypto_aead_chacha20poly1305_ietf_decrypt(
      data, &DATA_LEN, NULL, ciphertext, CIPHERTEXT_LEN, additional_data,
      ADDITIONAL_DATA_LEN, nonce, client_rx);

  free(ciphertext);
  free(nonce);
  sodium_free(client_rx);

  if (decrypted == 0) return 0;

  return -9;
}
