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
/* #include <string.h> */

#include "./shamir/polynomial.c"

/* #include "../../libsodium/src/libsodium/randombytes/randombytes.c" */
extern uint32_t randombytes_js();

__attribute__((used)) int
split_secret(const int sharesLen, const int threshold, const int secretLen,
             const uint8_t secret[secretLen],
             uint8_t shares[sharesLen][secretLen + 1])
{
  size_t i, j;

  if (sharesLen > FIELD - 1) return -3;
  if (sharesLen < threshold) return -2;
  if (threshold < 2) return -1;

  uint8_t coefficients[threshold];
  /* uint8_t *coefficients = malloc(threshold * sizeof(uint8_t)); */

  for (i = 0; i < secretLen; i++)
  {
    /* randombytes_buf(coefficients, threshold); */
    coefficients[0] = secret[i];
    for (j = 1; j < threshold; j++)
    {
      coefficients[j] = (uint8_t)randombytes_js();
    }

    for (j = 0; j < sharesLen; j++)
    {
      shares[j][i] = evaluate(threshold, coefficients, j + 1);

      if (i == secretLen - 1) shares[j][secretLen] = j + 1;
    }
  }

  /* free(coefficients); */

  return 0;
}

__attribute__((used)) int
restore_secret(const int sharesLen, const int secretLen,
               const uint8_t shares[sharesLen][secretLen + 1],
               uint8_t secret[secretLen])
{
  size_t i, j;

  if (sharesLen < 2)
    return -2; // throw new Error('Not enough shares provided');
  if (sharesLen > FIELD - 1)
    return -1; // throw new Error(`Need at most ${utils.FIELD - 1}
               // shares`);

  /* uint8_t points[sharesLen][2]; */
  uint8_t(*points)[2] = malloc(sharesLen * sizeof(uint8_t));

  for (i = 0; i < secretLen; i++)
  {
    for (j = 0; j < sharesLen; j++)
    {
      points[j][0] = shares[j][secretLen];
      points[j][1] = shares[j][i];
    }

    secret[i] = interpolate(sharesLen, points);
  }

  free(points);

  return 0;
}
