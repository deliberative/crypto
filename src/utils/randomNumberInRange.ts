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

import dcryptoMethodsModule from "../c/build/dcryptoMethodsModule";

import type { DCryptoMethodsModule } from "../c/build/dcryptoMethodsModule";

/**
 * @function
 * Returns a cryptographically random number between min and max.
 *
 * @param min: The minimum number.
 * @param max: The maximum number.
 * @param module: In case we want to cache the WASM loading.
 *
 * @returns number
 */
const randomNumberInRange = async (
  min: number,
  max: number,
  module?: DCryptoMethodsModule,
): Promise<number> => {
  if (module) return module._random_number_in_range(min, max);

  const wasmMemory = utilsMemory.randomNumberInRange(min, max);

  const dcryptoModule = await dcryptoMethodsModule({ wasmMemory });

  return dcryptoModule._random_number_in_range(min, max);
};

export default randomNumberInRange;
