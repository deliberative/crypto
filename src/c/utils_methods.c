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
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../../libsodium/src/libsodium/randombytes/randombytes.c"

__attribute__((used)) int
random_number_in_range(const int MIN, const int MAX)
{
  size_t i;

  const int RANGE = MAX - MIN;
  const int BYTES_NEEDED = ceil(log2(RANGE) / 8);
  const int MAX_RANGE = pow(pow(2, 8), BYTES_NEEDED);
  const int EXTENDED_RANGE = floor(MAX_RANGE / RANGE) * RANGE;

  uint8_t *randomBytes = malloc(BYTES_NEEDED * sizeof(uint8_t));

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

/* __attribute__((used)) int */
/* array_random_shuffle(const int size, const uint8_t array[size], */
/*                      uint8_t shuffled[size]) */
/* { */
/*   memcpy(shuffled, array, size); */
/*  */
/*   if (size < 2) return 0; */
/*  */
/*   size_t i, j; */
/*   int temp; */
/*  */
/*   for (i = size - 1; i > 0; i--) */
/*   { */
/*     j = random_number_in_range(0, i + 1); */
/*  */
/*     temp = shuffled[i]; */
/*     shuffled[i] = shuffled[j]; */
/*     shuffled[j] = temp; */
/*   } */
/*  */
/*   return 0; */
/* } */
/*  */
/* __attribute__((used)) int */
/* array_random_subset(const int size, const int subsetSize, */
/*                     const uint8_t array[size], uint8_t subset[subsetSize]) */
/* { */
/*   if (size < subsetSize) */
/*   { */
/*     return -1; */
/*   } */
/*   else if (size == subsetSize) */
/*   { */
/*     array_random_shuffle(size, array, subset); */
/*   } */
/*   else */
/*   { */
/*     uint8_t *randomShuffledArray = malloc(size * sizeof(uint8_t)); */
/*  */
/*     array_random_shuffle(size, array, randomShuffledArray); */
/*  */
/*     memcpy(subset, randomShuffledArray, subsetSize); */
/*  */
/*     free(randomShuffledArray); */
/*   } */
/*  */
/*   return 0; */
/* } */
