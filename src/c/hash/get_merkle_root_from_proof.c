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

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "../../../libsodium/src/libsodium/include/sodium/crypto_hash_sha512.h"

__attribute__((used)) int
get_merkle_root_from_proof(const int PROOF_LEN,
                           const uint8_t element_hash[crypto_hash_sha512_BYTES],
                           const uint8_t proof[PROOF_LEN],
                           uint8_t root[crypto_hash_sha512_BYTES])
{
  if (PROOF_LEN % (crypto_hash_sha512_BYTES + 1) != 0) return -1;
  int NODES_LEN = PROOF_LEN / (crypto_hash_sha512_BYTES + 1);

  memcpy(root, element_hash, crypto_hash_sha512_BYTES);

  if (NODES_LEN == 1)
  {
    bool isOne = true;
    for (int i = 0; i < crypto_hash_sha512_BYTES + 1; i++)
    {
      if (proof[i] != 1)
      {
        isOne = false;
        break;
      }
    }

    // Single element tree
    if (isOne) return 0;
  }

  size_t i, position;

  uint8_t *concat_hashes = malloc(2 * crypto_hash_sha512_BYTES);

  for (i = 0; i < NODES_LEN; i++)
  {
    position
        = proof[i * (crypto_hash_sha512_BYTES + 1) + crypto_hash_sha512_BYTES];
    if (position != 0 && position != 1)
    {
      free(concat_hashes);

      return -1;
    }

    // Proof artifact goes to the left
    if (position == 0)
    {
      memcpy(concat_hashes, &proof[i * (crypto_hash_sha512_BYTES + 1)],
             crypto_hash_sha512_BYTES);
      memcpy(&concat_hashes[crypto_hash_sha512_BYTES], root,
             crypto_hash_sha512_BYTES);
    }
    else
    {
      memcpy(concat_hashes, root, crypto_hash_sha512_BYTES);
      memcpy(&concat_hashes[crypto_hash_sha512_BYTES],
             &proof[i * (crypto_hash_sha512_BYTES + 1)],
             crypto_hash_sha512_BYTES);
    }

    int res
        = crypto_hash_sha512(root, concat_hashes, 2 * crypto_hash_sha512_BYTES);
  }

  free(concat_hashes);

  return 0;
}
