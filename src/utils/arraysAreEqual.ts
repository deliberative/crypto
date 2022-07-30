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

const arraysAreEqual = (array1: Uint8Array, array2: Uint8Array) => {
  const array1Length = array1.length;
  if (array1Length !== array2.length) return false;

  for (let i = 0; i < array1Length; i++) {
    if (array1[i] !== array2[i]) return false;
  }

  return true;
};

// import loadArrayMethods from "./loadArrayMethods";
//
// const arraysAreEqual = async (
//   arr1: Uint8Array,
//   arr2: Uint8Array,
//   wasm?: WebAssembly.Exports,
// ): Promise<boolean> => {
//   const len = arr1.length;
//   if (len !== arr2.length) return false;
//
//   const memoryLen = 2 * len * Uint8Array.BYTES_PER_ELEMENT;
//   wasm = wasm ? wasm : await loadArrayMethods(memoryLen);
//   const areEqual = wasm.arrays_are_equal as CallableFunction;
//   const memory = wasm.memory as WebAssembly.Memory;
//
//   let offset = 0;
//   const array1 = new Uint8Array(memory.buffer, offset, len);
//   array1.set([...arr1]);
//
//   offset += len * Uint8Array.BYTES_PER_ELEMENT;
//   const array2 = new Uint8Array(memory.buffer, offset, len);
//   array2.set([...arr2]);
//
//   const result = areEqual(len, array1.byteOffset, array2.byteOffset) as number;
//
//   return result === 1;
// };

export default arraysAreEqual;
