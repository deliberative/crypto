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
#include <stdlib.h>
#include <string.h>

#include "./shamir.h"

__attribute__((used)) int
restore_secret(const int SHARES_LEN, const int SECRET_LEN,
               const uint8_t shares[SHARES_LEN][SECRET_LEN + 1],
               uint8_t secret[SECRET_LEN])
{
  size_t i, j;

  if (SHARES_LEN < 2)
    return -2; // throw new Error('Not enough shares provided');
  if (SHARES_LEN > FIELD - 1)
    return -1; // throw new Error(`Need at most ${utils.FIELD - 1}
               // shares`);

  uint8_t(*points)[2] = malloc(sizeof(uint8_t[SHARES_LEN][2]));
  /* uint8_t *points = malloc(SHARES_LEN * 2); */

  for (i = 0; i < SECRET_LEN; i++)
  {
    for (j = 0; j < SHARES_LEN; j++)
    {
      /* points[j * 2] = shares[j * (SECRET_LEN + 1) + SECRET_LEN]; */
      /* memcpy(&points[j * 2], &shares[j * (SECRET_LEN + 1) + SECRET_LEN], */
      /*        sizeof(uint8_t)); */
      /* memcpy(&points[j * 2], &shares[j][SECRET_LEN], sizeof(uint8_t)); */
      /* points[j][0] = shares[j][SECRET_LEN]; */
      memcpy(&points[j][0], &shares[j][SECRET_LEN], sizeof(uint8_t));
      /* points[j * 2 + 1] = shares[j * (SECRET_LEN + 1) + i]; */
      /* memcpy(&points[j * 2 + 1], &shares[j * (SECRET_LEN + 1) + i], */
      /*        sizeof(uint8_t)); */
      /* memcpy(&points[j * 2 + 1], &shares[j][i], sizeof(uint8_t)); */
      /* points[j][1] = shares[j][i]; */
      memcpy(&points[j][1], &shares[j][i], sizeof(uint8_t));
    }

    secret[i] = interpolate(SHARES_LEN, points);
  }

  free(points);

  return 0;
}
