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

#include "../../../libsodium/src/libsodium/include/sodium/crypto_pwhash_argon2id.h"
#include "../../../libsodium/src/libsodium/include/sodium/crypto_sign_ed25519.h"

__attribute__((used)) int
argon2(const unsigned int MNEMONIC_LEN,
       uint8_t seed[crypto_sign_ed25519_SEEDBYTES],
       const char mnemonic[MNEMONIC_LEN],
       const uint8_t salt[crypto_pwhash_argon2id_SALTBYTES])
{
  return crypto_pwhash_argon2id(seed, crypto_sign_ed25519_SEEDBYTES, mnemonic,
                                MNEMONIC_LEN, salt,
                                crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE,
                                crypto_pwhash_argon2id_MEMLIMIT_INTERACTIVE,
                                crypto_pwhash_argon2id_ALG_ARGON2ID13);
}
