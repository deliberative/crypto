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

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "./shamir/polynomial.c"

#include "../../libsodium/src/libsodium/randombytes/randombytes.c"

__attribute__((used)) int
split_secret(const int SHARES_LEN, const int THRESHOLD, const int SECRET_LEN,
             const uint8_t secret[SECRET_LEN],
             uint8_t shares[SHARES_LEN * (SECRET_LEN + 1)])
{
  size_t i, j;

  if (SHARES_LEN > FIELD - 1) return -3;
  if (SHARES_LEN < THRESHOLD) return -2;
  if (THRESHOLD < 2) return -1;

  uint8_t *coefficients = malloc(THRESHOLD * sizeof(uint8_t));

  for (i = 0; i < SECRET_LEN; i++)
  {
    randombytes_buf(coefficients, THRESHOLD);
    coefficients[0] = secret[i];

    for (j = 0; j < SHARES_LEN; j++)
    {
      shares[j * (SECRET_LEN + 1) + i]
          = evaluate(THRESHOLD, coefficients, j + 1);
      /* shares[j][i] = evaluate(THRESHOLD, coefficients, j + 1); */

      if (i == SECRET_LEN - 1)
      {
        shares[j * (SECRET_LEN + 1) + SECRET_LEN] = j + 1;
        /* shares[j][SECRET_LEN] = j + 1; */
      }
    }
  }

  free(coefficients);

  return 0;
}

__attribute__((used)) int
restore_secret(const int SHARES_LEN, const int SECRET_LEN,
               const uint8_t shares[SHARES_LEN * (SECRET_LEN + 1)],
               uint8_t secret[SECRET_LEN])
{
  size_t i, j;

  if (SHARES_LEN < 2)
    return -2; // throw new Error('Not enough shares provided');
  if (SHARES_LEN > FIELD - 1)
    return -1; // throw new Error(`Need at most ${utils.FIELD - 1}
               // shares`);

  /* uint8_t(*points)[2] = malloc(SHARES_LEN * sizeof(*points)); */
  uint8_t *points = malloc(SHARES_LEN * 2 * sizeof(uint8_t));

  for (i = 0; i < SECRET_LEN; i++)
  {
    for (j = 0; j < SHARES_LEN; j++)
    {
      points[j * 2] = shares[j * (SECRET_LEN + 1) + SECRET_LEN];
      /* points[j][0] = shares[j][SECRET_LEN]; */
      points[j * 2 + 1] = shares[j * (SECRET_LEN + 1) + i];
      /* points[j][1] = shares[j][i]; */
    }

    secret[i] = interpolate(SHARES_LEN, points);
  }

  free(points);

  return 0;
}
