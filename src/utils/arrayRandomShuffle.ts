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

import utilsMemory from "./memory";
import randomNumberInRange from "./randomNumberInRange";

import dcryptoMethodsModule from "../c/build/dcryptoMethodsModule";

/** Fisher-Yates Shuffle */
const arrayRandomShuffle = async <T>(array: T[]): Promise<T[]> => {
  const n = array.length;

  // If array has <2 items, there is nothing to do
  if (n < 2) return array;

  const shuffled = [...array];

  const wasmMemory = utilsMemory.randomNumberInRangeMemory(0, n);
  const module = await dcryptoMethodsModule({ wasmMemory });

  for (let i = n - 1; i > 0; i--) {
    const j = await randomNumberInRange(0, i + 1, module);
    const temp = shuffled[i];
    shuffled[i] = shuffled[j];
    shuffled[j] = temp;
  }

  return shuffled;
};

export default arrayRandomShuffle;
