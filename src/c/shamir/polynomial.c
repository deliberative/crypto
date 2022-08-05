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

#include "ring.c"

int
/* interpolate(const size_t sharesLen, const uint8_t points[sharesLen][2]) */
interpolate(const size_t SHARES_LEN, const uint8_t points[SHARES_LEN * 2])
{
  size_t i, j;

  const int x = 0;

  int result = 0;

  for (i = 0; i < SHARES_LEN; i++)
  {
    int weight = 1;

    const int aX = points[i * 2];
    /* const int aX = points[i][0]; */
    const int aY = points[i * 2 + 1];
    /* const int aY = points[i][1]; */

    for (j = 0; j < SHARES_LEN; j++)
    {
      if (i == j) continue;

      const int bX = points[j * 2];
      /* const int bX = points[j][0]; */

      weight = multiply(weight, divide(subtract(x, bX), subtract(aX, bX)));
    }

    result = add(result, multiply(aY, weight));
  }

  return result;
};

int
degree(const size_t threshold, const uint8_t coefficients[threshold])
{
  int i = threshold - 1;

  do
  {
    if (coefficients[i] != 0) return i;
  } while (--i > 0);

  return 0;
};

// Compute y from x
int
evaluate(const size_t threshold, const uint8_t coefficients[threshold],
         const int x)
{
  if (x == 0) return coefficients[0];

  const int d = degree(threshold, coefficients);

  int y = coefficients[d];

  int i = d - 1;
  do
  {
    y = add(multiply(y, x), coefficients[i]);
  } while (--i >= 0);

  return y;
};
