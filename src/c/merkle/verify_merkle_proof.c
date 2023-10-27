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
verify_merkle_proof(
    const unsigned int PROOF_ARTIFACTS_LEN,
    const uint8_t element_hash[crypto_hash_sha512_BYTES],
    const uint8_t root[crypto_hash_sha512_BYTES],
    const uint8_t proof[PROOF_ARTIFACTS_LEN][crypto_hash_sha512_BYTES + 1])
{
  size_t i, position;

  if (PROOF_ARTIFACTS_LEN == 1)
  {
    bool isOne = true;
    for (i = 0; i < crypto_hash_sha512_BYTES + 1; i++)
    {
      if (proof[0][i] != 1)
      {
        isOne = false;
        break;
      }
    }

    // Single element tree
    if (isOne)
    {
      for (i = 0; i < crypto_hash_sha512_BYTES; i++)
      {
        if (element_hash[i] != root[i]) return 1;
      }

      return 0;
    }
  }

  uint8_t(*concat_hashes)[crypto_hash_sha512_BYTES]
      = malloc(sizeof(uint8_t[2][crypto_hash_sha512_BYTES]));
  if (concat_hashes == NULL) return -1;

  uint8_t *hash = malloc(sizeof(uint8_t[crypto_hash_sha512_BYTES]));
  if (hash == NULL)
  {
    free(concat_hashes);

    return -2;
  }

  memcpy(hash, element_hash, crypto_hash_sha512_BYTES);

  int res;

  /* for (i = 0; i < NODES_LEN; i++) */
  for (i = 0; i < PROOF_ARTIFACTS_LEN; i++)
  {
    position = proof[i][crypto_hash_sha512_BYTES];
    if (position != 0 && position != 1)
    {
      free(hash);
      free(concat_hashes);

      return -3;
    }

    // Proof artifact goes to the left
    if (position == 0)
    {
      memcpy(&concat_hashes[0], &proof[i], crypto_hash_sha512_BYTES);
      memcpy(&concat_hashes[1], &hash[0], crypto_hash_sha512_BYTES);
    }
    else
    {
      memcpy(&concat_hashes[0], &hash[0], crypto_hash_sha512_BYTES);
      memcpy(&concat_hashes[1], &proof[i], crypto_hash_sha512_BYTES);
    }

    res = crypto_hash_sha512(hash, *concat_hashes,
                             2 * crypto_hash_sha512_BYTES);
    if (res != 0)
    {
      free(concat_hashes);
      free(hash);

      return -4;
    }
  }

  free(concat_hashes);
  res = memcmp(hash, root, crypto_hash_sha512_BYTES);
  free(hash);

  if (res != 0) return 1;

  return 0;
}
