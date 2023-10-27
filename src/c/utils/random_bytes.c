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
#include <stddef.h>
#include <stdint.h>

uint32_t
randombytes_random(void)
{
  return EM_ASM_INT_V({
    if (Module.getRandomValue === undefined) {
        try {
            var window_ = 'object' === typeof window ? window : self;
            var crypto_ = typeof window_.crypto !== 'undefined' ? window_.crypto : window_.msCrypto;
            var randomValuesStandard = function() {
                var buf = new Uint32Array(1);
                crypto_.getRandomValues(buf);
                return buf[0] >>> 0;
            };
            randomValuesStandard();
            Module.getRandomValue = randomValuesStandard;
        } catch (e) {
            try {
                var crypto = require('crypto');
                var randomValueNodeJS = function() {
                    var buf = crypto['randomBytes'](4);
                    return (buf[0] << 24 | buf[1] << 16 | buf[2] << 8 | buf[3]) >>> 0;
                };
                randomValueNodeJS();
                Module.getRandomValue = randomValueNodeJS;
            } catch (e) {
                throw 'No secure random number generator found';
            }
        }
    }
    return Module.getRandomValue();
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
