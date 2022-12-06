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

#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../../libsodium/src/libsodium/randombytes/randombytes.c"
#include "../../libsodium/src/libsodium/sodium/codecs.c"
#include "../../libsodium/src/libsodium/sodium/core.c"
#include "../../libsodium/src/libsodium/sodium/utils.c"

// SHA512
#include "../../libsodium/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c"

// Argon2
#include "../../libsodium/src/libsodium/crypto_pwhash/argon2/argon2-core.c"
#include "../../libsodium/src/libsodium/crypto_pwhash/argon2/argon2-encoding.c"
#include "../../libsodium/src/libsodium/crypto_pwhash/argon2/argon2-fill-block-ref.c"
#include "../../libsodium/src/libsodium/crypto_pwhash/argon2/argon2.c"
#include "../../libsodium/src/libsodium/crypto_pwhash/argon2/blake2b-long.c"
#include "../../libsodium/src/libsodium/crypto_pwhash/argon2/pwhash_argon2id.c"

// Ed25519
#include "../../libsodium/src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c"
#include "../../libsodium/src/libsodium/crypto_sign/ed25519/ref10/keypair.c"
#include "../../libsodium/src/libsodium/crypto_sign/ed25519/ref10/open.c"
#include "../../libsodium/src/libsodium/crypto_sign/ed25519/ref10/sign.c"
#include "../../libsodium/src/libsodium/crypto_verify/sodium/verify.c"

// AEAD Chacha20Poly1305
#include "../../libsodium/src/libsodium/crypto_aead/chacha20poly1305/sodium/aead_chacha20poly1305.c"
#include "../../libsodium/src/libsodium/crypto_generichash/blake2b/ref/blake2b-compress-ref.c"
#include "../../libsodium/src/libsodium/crypto_generichash/blake2b/ref/blake2b-ref.c"
#include "../../libsodium/src/libsodium/crypto_generichash/blake2b/ref/generichash_blake2b.c"
#include "../../libsodium/src/libsodium/crypto_generichash/crypto_generichash.c"
#include "../../libsodium/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna.c"
#include "../../libsodium/src/libsodium/crypto_onetimeauth/poly1305/onetimeauth_poly1305.c"
#include "../../libsodium/src/libsodium/crypto_stream/chacha20/ref/chacha20_ref.c"
#include "../../libsodium/src/libsodium/crypto_stream/chacha20/stream_chacha20.c"

// Diffie Hellman
#include "../../libsodium/src/libsodium/crypto_kx/crypto_kx.c"
#include "../../libsodium/src/libsodium/crypto_scalarmult/crypto_scalarmult.c"
#include "../../libsodium/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c"
#include "../../libsodium/src/libsodium/crypto_scalarmult/curve25519/scalarmult_curve25519.c"
#include "../../libsodium/src/libsodium/crypto_scalarmult/ed25519/ref10/scalarmult_ed25519_ref10.c"

// Utils
#include "./utils/items_indexes_in_array.c"
#include "./utils/random_bytes.c"
#include "./utils/random_number_in_range.c"

// Hash
#include "./hash/argon2.c"
#include "./hash/sha512.c"

// Merkle
#include "./hash/get_merkle_proof.c"
#include "./hash/get_merkle_root.c"
#include "./hash/get_merkle_root_from_proof.c"
#include "./hash/verify_merkle_proof.c"

// Shamir
#include "./shamir/polynomial.c"
#include "./shamir/restore_secret.c"
#include "./shamir/split_secret.c"

// Encryption
#include "./encrypt/calculate_nonce.c"
#include "./encrypt/e2e_encrypt_data.c"
#include "./encrypt/forward_secretbox_encrypt.c"
#include "./encrypt/key_encrypt_data.c"

// Decryption
#include "./decrypt/e2e_decrypt_data.c"
#include "./decrypt/forward_secretbox_decrypt_data.c"
#include "./decrypt/key_decrypt_data.c"

__attribute__((used)) int
new_keypair(uint8_t public_key[crypto_sign_ed25519_PUBLICKEYBYTES],
            uint8_t secret_key[crypto_sign_ed25519_SECRETKEYBYTES])
{
  return crypto_sign_ed25519_keypair(public_key, secret_key);
}

__attribute__((used)) int
keypair_from_seed(uint8_t public_key[crypto_sign_ed25519_PUBLICKEYBYTES],
                  uint8_t secret_key[crypto_sign_ed25519_SECRETKEYBYTES],
                  const uint8_t seed[crypto_sign_ed25519_SEEDBYTES])
{
  return crypto_sign_ed25519_seed_keypair(public_key, secret_key, seed);
}

__attribute__((used)) int
keypair_from_secret_key(
    uint8_t public_key[crypto_sign_ed25519_PUBLICKEYBYTES],
    const uint8_t secret_key[crypto_sign_ed25519_SECRETKEYBYTES])
{
  memcpy(public_key, secret_key + crypto_sign_ed25519_SEEDBYTES,
         crypto_sign_ed25519_PUBLICKEYBYTES);

  return 0;
}

__attribute__((used)) int
sign_data(const int DATA_LEN, const uint8_t data[DATA_LEN],
          uint8_t signature[crypto_sign_ed25519_BYTES],
          const uint8_t secret_key[crypto_sign_ed25519_SECRETKEYBYTES])
{
  unsigned long long SIGNATURE_LEN = crypto_sign_ed25519_BYTES;

  return crypto_sign_ed25519_detached(signature, &SIGNATURE_LEN, data, DATA_LEN,
                                      secret_key);
}

__attribute__((used)) int
verify_data(const int DATA_LEN, const uint8_t data[DATA_LEN],
            const uint8_t signature[crypto_sign_ed25519_BYTES],
            const uint8_t public_key[crypto_sign_ed25519_PUBLICKEYBYTES])
{
  return crypto_sign_ed25519_verify_detached(signature, data, DATA_LEN,
                                             public_key);
}
