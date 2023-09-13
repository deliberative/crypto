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

/* Returns (ephemeral_pk || nonce || encrypted_data || auth tag)  */
__attribute__((used)) int
forward_secretbox_encrypt_data(
    const int DATA_LEN, const uint8_t data[DATA_LEN],
    const uint8_t public_key[crypto_sign_ed25519_PUBLICKEYBYTES],
    const int ADDITIONAL_DATA_LEN,
    const uint8_t additional_data[ADDITIONAL_DATA_LEN],
    uint8_t encrypted[crypto_scalarmult_curve25519_BYTES
                      + crypto_aead_chacha20poly1305_ietf_NPUBBYTES + DATA_LEN
                      + crypto_aead_chacha20poly1305_ietf_ABYTES])
{
  unsigned long long CIPHERTEXT_LEN
      = DATA_LEN + crypto_aead_chacha20poly1305_ietf_ABYTES;
  uint8_t *ciphertext = sodium_malloc(CIPHERTEXT_LEN);
  if (ciphertext == NULL) return -1;

  uint8_t *ephemeral_x25519_pk = malloc(crypto_scalarmult_curve25519_BYTES);
  if (ephemeral_x25519_pk == NULL)
  {
    sodium_free(ciphertext);

    return -2;
  }

  uint8_t *ephemeral_x25519_sk
      = sodium_malloc(crypto_scalarmult_curve25519_SCALARBYTES);
  if (ephemeral_x25519_sk == NULL)
  {
    sodium_free(ciphertext);
    free(ephemeral_x25519_pk);

    return -3;
  }

  crypto_kx_keypair(ephemeral_x25519_pk, ephemeral_x25519_sk);

  uint8_t *x25519_pk = malloc(crypto_scalarmult_curve25519_BYTES);
  if (x25519_pk == NULL)
  {
    sodium_free(ciphertext);
    free(ephemeral_x25519_pk);
    sodium_free(ephemeral_x25519_sk);

    return -4;
  }

  int converted = crypto_sign_ed25519_pk_to_curve25519(x25519_pk, public_key);
  if (converted != 0)
  {
    free(x25519_pk);
    sodium_free(ciphertext);
    free(ephemeral_x25519_pk);
    sodium_free(ephemeral_x25519_sk);

    return -5;
  }

  uint8_t *server_tx = sodium_malloc(crypto_kx_SESSIONKEYBYTES);
  if (server_tx == NULL)
  {
    free(x25519_pk);
    sodium_free(ciphertext);
    free(ephemeral_x25519_pk);
    sodium_free(ephemeral_x25519_sk);

    return -6;
  }

  int created = crypto_kx_server_session_keys(
      NULL, server_tx, ephemeral_x25519_pk, ephemeral_x25519_sk, x25519_pk);
  sodium_free(ephemeral_x25519_sk);
  if (created != 0)
  {
    free(x25519_pk);
    sodium_free(ciphertext);
    free(ephemeral_x25519_pk);
    sodium_free(server_tx);

    return -7;
  }

  uint8_t *nonce = malloc(crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
  if (nonce == NULL)
  {
    free(x25519_pk);
    sodium_free(ciphertext);
    free(ephemeral_x25519_pk);
    sodium_free(server_tx);

    return -8;
  }

  calculate_nonce(nonce);
  free(x25519_pk);

  crypto_aead_chacha20poly1305_ietf_encrypt(
      ciphertext, &CIPHERTEXT_LEN, data, DATA_LEN, additional_data,
      ADDITIONAL_DATA_LEN, NULL, nonce, server_tx);
  sodium_free(server_tx);

  memcpy(encrypted, ephemeral_x25519_pk, crypto_scalarmult_curve25519_BYTES);
  free(ephemeral_x25519_pk);

  memcpy(encrypted + crypto_scalarmult_curve25519_BYTES, nonce,
         crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
  free(nonce);

  int KEY_NONCE_LEN = crypto_scalarmult_curve25519_BYTES
                      + crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
  memcpy(encrypted + KEY_NONCE_LEN, ciphertext, CIPHERTEXT_LEN);
  sodium_free(ciphertext);

  return 0;
}
