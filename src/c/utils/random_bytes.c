// Copyright (C) 2023 Deliberative Technologies P.C.
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

#include <assert.h>
#include <emscripten.h>
#include <stdint.h>
#include <stddef.h>

uint32_t
randombytes_random(void)
{
  return EM_ASM_INT_V({
    const crypto = globalThis.crypto;
    const buf = new Uint32Array(1);
    crypto.getRandomValues(buf);
    return buf[0] >>> 0;
  });
}

void
randombytes_buf(void *const buf, const size_t size)
{
  if (size > (size_t)0U)
  {
    unsigned char *p = (unsigned char *)buf;
    size_t i;

    for (i = (size_t)0U; i < size; i++)
    {
      p[i] = (unsigned char)randombytes_random();
    }
  }
}

void
randombytes(unsigned char *const buf, const unsigned long long buf_len)
{
  assert(buf_len <= SIZE_MAX);
  randombytes_buf(buf, (size_t)buf_len);
}

__attribute__((used)) int
random_bytes(const unsigned int SIZE, uint8_t array[SIZE])
{
  randombytes_buf(array, SIZE);

  return 0;
}
