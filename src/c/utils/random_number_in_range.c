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
#include <stdint.h>
#include <stdlib.h>

#include "../../../libsodium/src/libsodium/include/sodium.h"

__attribute__((used)) int
random_number_in_range(const int MIN, const int MAX)
{
  size_t i;

  const unsigned int RANGE = MAX - MIN;
  const unsigned int BYTES_NEEDED = ceil(log2(RANGE) / 8);
  const unsigned int MAX_RANGE = pow(pow(2, 8), BYTES_NEEDED);
  const unsigned int EXTENDED_RANGE = floor(MAX_RANGE / RANGE) * RANGE;

  uint8_t *randomBytes = malloc(sizeof(uint8_t[BYTES_NEEDED]));
  if (randomBytes == NULL) return -1;

  int randomInteger = EXTENDED_RANGE;
  while (randomInteger >= EXTENDED_RANGE)
  {
    randombytes_buf(randomBytes, BYTES_NEEDED);

    randomInteger = 0;
    for (i = 0; i < BYTES_NEEDED; i++)
    {
      randomInteger <<= 8;
      randomInteger += randomBytes[i];
    }

    if (randomInteger < EXTENDED_RANGE)
    {
      free(randomBytes);
      randomInteger %= RANGE;

      return MIN + randomInteger;
    }
  }

  free(randomBytes);

  return randomInteger;
}
