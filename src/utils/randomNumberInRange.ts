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

import loadUtils from "../wasmLoaders/utils";

const randomNumberInRange = async (
  min: number,
  max: number,
  wasm?: WebAssembly.Exports,
): Promise<number> => {
  const bytesNeeded = Math.ceil(Math.log2(max - min) / 8);
  const memoryLen = (bytesNeeded + 3 * 4) * Uint8Array.BYTES_PER_ELEMENT;
  wasm = wasm || (await loadUtils(memoryLen));
  const random = wasm.random_number_in_range as CallableFunction;

  const result = random(min, max) as number;

  return result;
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
