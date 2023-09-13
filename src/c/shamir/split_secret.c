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

#include "../utils/utils.h"

__attribute__((used)) int
split_secret(const unsigned int SHARES_LEN, const unsigned int THRESHOLD,
             const unsigned int SECRET_LEN, const uint8_t secret[SECRET_LEN],
             uint8_t shares[SHARES_LEN][SECRET_LEN + 1])
{
  size_t i, j;

  if (SHARES_LEN > FIELD - 1) return -3;
  if (SHARES_LEN < THRESHOLD) return -2;
  if (THRESHOLD < 2) return -1;

  uint8_t *coefficients = malloc(THRESHOLD);
  if (coefficients == NULL) return -4;

  for (i = 0; i < SECRET_LEN; i++)
  {
    random_bytes(THRESHOLD, coefficients);
    coefficients[0] = secret[i];

    for (j = 0; j < SHARES_LEN; j++)
    {
      /* shares[j * (SECRET_LEN + 1) + i] */
      /* = evaluate(THRESHOLD, coefficients, j + 1); */

      shares[j][i] = evaluate(THRESHOLD, coefficients, j + 1);

      if (i == SECRET_LEN - 1)
      {
        /* shares[j * (SECRET_LEN + 1) + SECRET_LEN] = j + 1; */
        shares[j][SECRET_LEN] = j + 1;
      }
    }
  }

  free(coefficients);

  return 0;
}
