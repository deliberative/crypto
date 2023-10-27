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

#include "../../../libsodium/src/libsodium/include/sodium.h"
// #include
// "../../../libsodium/src/libsodium/include/sodium/crypto_hash_sha512.h"

__attribute__((used)) int
sha512(const unsigned int DATA_LEN, const uint8_t data[DATA_LEN],
       uint8_t hash[crypto_hash_sha512_BYTES])
{
  return crypto_hash_sha512(hash, data, DATA_LEN);
}
