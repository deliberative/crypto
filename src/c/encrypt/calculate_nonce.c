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
#include "../../../libsodium/src/libsodium/include/sodium/crypto_hash_sha512.h"
#include "../../../libsodium/src/libsodium/include/sodium/randombytes.h"
#include "../../../libsodium/src/libsodium/include/sodium/utils.h"

__attribute__((used)) void
calculate_nonce(uint8_t nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES])
{
  uint8_t *nonce_random_vector = sodium_malloc(crypto_hash_sha512_BYTES);
  randombytes_buf(nonce_random_vector, crypto_hash_sha512_BYTES);

  uint8_t *nonce_sha512 = malloc(crypto_hash_sha512_BYTES);
  crypto_hash_sha512(nonce_sha512, nonce_random_vector,
                     crypto_hash_sha512_BYTES);
  sodium_free(nonce_random_vector);

  memcpy(nonce, nonce_sha512 + crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
         crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
  free(nonce_sha512);
}
