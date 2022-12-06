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

#include "../utils/utils.h"

#include "../../../libsodium/src/libsodium/include/sodium/crypto_hash_sha512.h"

// The result is the proof length
__attribute__((used)) int
get_merkle_proof(
    const int LEAVES_LEN,
    const uint8_t leaves_hashed[LEAVES_LEN * crypto_hash_sha512_BYTES],
    const uint8_t element_hash[crypto_hash_sha512_BYTES],
    uint8_t proof[LEAVES_LEN * (crypto_hash_sha512_BYTES + 1)])
{
  size_t i, j, k;

  int32_t index[1];
  items_indexes_in_array(LEAVES_LEN, 1, leaves_hashed, element_hash, index);
  if (index[0] == -1) return -1;

  int element_of_interest = index[0];

  uint8_t *hashes = malloc(LEAVES_LEN * crypto_hash_sha512_BYTES);
  memcpy(hashes, leaves_hashed, LEAVES_LEN * crypto_hash_sha512_BYTES);

  uint8_t *concat_hashes = malloc(2 * crypto_hash_sha512_BYTES);
  uint8_t *hash = malloc(crypto_hash_sha512_BYTES);

  int l;
  int leaves = LEAVES_LEN;
  int res;
  bool oddLeaves;
  // Counts the index of proof artifacts.
  k = 0;
  do
  {
    // Counts the index of the elements of the new array of hashes.
    j = 0;
    oddLeaves = leaves % 2 != 0;
    for (i = 0; i < leaves; i += 2)
    {
      if (oddLeaves && i + 1 == leaves)
      {
        memcpy(concat_hashes, &hashes[i * crypto_hash_sha512_BYTES],
               crypto_hash_sha512_BYTES);
        memcpy(&concat_hashes[crypto_hash_sha512_BYTES],
               &hashes[i * crypto_hash_sha512_BYTES], crypto_hash_sha512_BYTES);

        if (i == element_of_interest)
        {
          memcpy(&proof[k * (crypto_hash_sha512_BYTES + 1)],
                 &hashes[i * crypto_hash_sha512_BYTES],
                 crypto_hash_sha512_BYTES);
          // We do not care if left(0) or right(1) since hash of itself
          proof[k++ * (crypto_hash_sha512_BYTES + 1) + crypto_hash_sha512_BYTES]
              = 0;
          element_of_interest = j;
        }
      }
      else
      {
        memcpy(concat_hashes, &hashes[i * crypto_hash_sha512_BYTES],
               crypto_hash_sha512_BYTES);
        memcpy(&concat_hashes[crypto_hash_sha512_BYTES],
               &hashes[(i + 1) * crypto_hash_sha512_BYTES],
               crypto_hash_sha512_BYTES);

        if (i == element_of_interest)
        {
          memcpy(&proof[k * (crypto_hash_sha512_BYTES + 1)],
                 &hashes[(i + 1) * crypto_hash_sha512_BYTES],
                 crypto_hash_sha512_BYTES);
          // Proof artifact needs to go to the right when concatenated with
          // element.
          proof[k++ * (crypto_hash_sha512_BYTES + 1) + crypto_hash_sha512_BYTES]
              = 1;
          element_of_interest = j;
        }
        else if (i + 1 == element_of_interest)
        {
          memcpy(&proof[k * (crypto_hash_sha512_BYTES + 1)],
                 &hashes[i * crypto_hash_sha512_BYTES],
                 crypto_hash_sha512_BYTES);
          // Proof artifact needs to go to the left when concatenated with
          // element.
          proof[k++ * (crypto_hash_sha512_BYTES + 1) + crypto_hash_sha512_BYTES]
              = 0;
          element_of_interest = j;
        }
      }

      crypto_hash_sha512(hash, concat_hashes, 2 * crypto_hash_sha512_BYTES);
      memcpy(&hashes[j++ * crypto_hash_sha512_BYTES], hash,
             crypto_hash_sha512_BYTES);
    }

    int l = ceil(leaves / 2);
    memset(&hashes[l * crypto_hash_sha512_BYTES], 0,
           (LEAVES_LEN - l) * crypto_hash_sha512_BYTES);
    leaves = l;
  } while (leaves > 1);

  free(hashes);
  free(concat_hashes);
  free(hash);

  return k * (crypto_hash_sha512_BYTES + 1);
}
