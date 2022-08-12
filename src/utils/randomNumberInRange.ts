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

// import loadUtils from "../wasmLoaders/utils";

import utilsMemory from "./memory";

import dcryptoMethodsModule from "../c/build/dcryptoMethodsModule";

import type { DCryptoMethodsModule } from "../c/build/dcryptoMethodsModule";

const randomNumberInRange = async (
  min: number,
  max: number,
  // wasm?: WebAssembly.Exports,
  // module?: UtilsMethodsModule,
  module?: DCryptoMethodsModule,
): Promise<number> => {
  if (module) return module._random_number_in_range(min, max);

  const wasmMemory = utilsMemory.randomNumberInRangeMemory(min, max);

  const dcryptoModule = await dcryptoMethodsModule({ wasmMemory });

  return dcryptoModule._random_number_in_range(min, max);
};

// import * as nacl from "tweetnacl";
//
// const randomNumberInRange = async (
//   min: number,
//   max: number,
// ): Promise<number> => {
//   return new Promise((resolve) => {
//     const range = max - min;
//     const bytesNeeded = Math.ceil(Math.log2(range) / 8);
//     const maximumRange = Math.pow(Math.pow(2, 8), bytesNeeded);
//     const extendedRange = Math.floor(maximumRange / range) * range;
//
//     let randomInteger = extendedRange;
//     while (randomInteger >= extendedRange) {
//       const randomBytes = nacl.randomBytes(bytesNeeded);
//       randomInteger = 0;
//
//       for (let i = 0; i < bytesNeeded; i++) {
//         randomInteger <<= 8;
//         randomInteger += randomBytes[i];
//       }
//
//       if (randomInteger < extendedRange) {
//         randomInteger %= range;
//
//         resolve(min + randomInteger);
//       }
//     }
//
//     resolve(randomInteger);
//   });
// };

export default randomNumberInRange;
