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

#include "../../../libsodium/src/libsodium/include/sodium.h"

// Output is an array of indexes of the elements
__attribute__((used)) void
items_indexes_in_array(
    const unsigned int ARRAY_LEN, const unsigned int ITEMS_ARRAY_LEN,
    const uint8_t array[ARRAY_LEN][crypto_hash_sha512_BYTES],
    const uint8_t items[ITEMS_ARRAY_LEN][crypto_hash_sha512_BYTES],
    int32_t indexes[ITEMS_ARRAY_LEN])
{
  size_t i, j, k;

  for (i = 0; i < ITEMS_ARRAY_LEN; i++)
  {
    // We start with all items unfound
    indexes[i] = -1;
  }

  if (ITEMS_ARRAY_LEN > ARRAY_LEN) return;

  int itemsFound = 0;
  for (i = 0; i < ARRAY_LEN; i++)
  {
    if (itemsFound == ITEMS_ARRAY_LEN) return;

    for (j = 0; j < ITEMS_ARRAY_LEN; j++)
    {
      bool found = true;
      for (k = 0; k < crypto_hash_sha512_BYTES; k++)
      {
        if (array[i][k] != items[j][k])
        {
          found = false;
          break;
        }
      }

      if (found)
      {
        indexes[j] = i;
        itemsFound++;

        break;
      }
    }
  }
}
