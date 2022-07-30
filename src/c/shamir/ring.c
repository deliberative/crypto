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

#include "constants.c"

// XOR
int
add(const int a, const int b)
{
  return a ^ b;
};

int
subtract(const int a, const int b)
{
  return add(a, b);
}

int
multiply(const int a, const int b)
{
  if (a == 0 || b == 0) return 0;

  const int sum = LOG[a] + LOG[b];

  return EXP[sum];
};

// multiply by the inverse of b
int
divide(const int a, const int b)
{
  if (a == 0) return 0;
  if (b == 0) return 0;

  return multiply(a, EXP[FIELD - 1 - LOG[b]]);
};
