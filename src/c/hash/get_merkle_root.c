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
#include <string.h>

#include "../../../libsodium/src/libsodium/include/sodium/crypto_hash_sha512.h"

__attribute__((used)) int
get_merkle_root(
    const int LEAVES_LEN,
    const uint8_t leaves_hashed[LEAVES_LEN * crypto_hash_sha512_BYTES],
    uint8_t root[crypto_hash_sha512_BYTES])
{
  size_t i, j;

  uint8_t *hashes = malloc(LEAVES_LEN * crypto_hash_sha512_BYTES);
  uint8_t *concat_hashes = malloc(2 * crypto_hash_sha512_BYTES);

  memcpy(hashes, leaves_hashed, LEAVES_LEN * crypto_hash_sha512_BYTES);

  int l;
  int leaves = LEAVES_LEN;
  int res;
  bool oddLeaves;
  // For every branch level.
  do
  {
    // Count hashes in current level.
    j = 0;
    oddLeaves = leaves % 2 != 0;
    for (i = 0; i < leaves; i += 2)
    {
      // We are at the last position to the right of a tree with odd number of
      // leaves.
      if (oddLeaves && i + 1 == leaves)
      {
        memcpy(concat_hashes, &hashes[i * crypto_hash_sha512_BYTES],
               crypto_hash_sha512_BYTES);
        // Concat leaf hash with itself.
        memcpy(&concat_hashes[crypto_hash_sha512_BYTES],
               &hashes[i * crypto_hash_sha512_BYTES], crypto_hash_sha512_BYTES);
      }
      else
      {
        memcpy(concat_hashes, &hashes[i * crypto_hash_sha512_BYTES],
               crypto_hash_sha512_BYTES);
        // In any other case concat leaf hash with the one on its right.
        memcpy(&concat_hashes[crypto_hash_sha512_BYTES],
               &hashes[(i + 1) * crypto_hash_sha512_BYTES],
               crypto_hash_sha512_BYTES);
      }

      crypto_hash_sha512(root, concat_hashes, 2 * crypto_hash_sha512_BYTES);
      memcpy(&hashes[j * crypto_hash_sha512_BYTES], root,
             crypto_hash_sha512_BYTES);
      j++;
    }

    l = ceil(leaves / 2);
    memset(&hashes[l * crypto_hash_sha512_BYTES], 0,
           (LEAVES_LEN - l) * crypto_hash_sha512_BYTES);
    leaves = l;
  } while (leaves > 1);

  memcpy(root, hashes, crypto_hash_sha512_BYTES);

  free(hashes);
  free(concat_hashes);

  return 0;
}
