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

import memoryLenToPages from "./memoryLenToPages";

const itemIndexInArray = (
  arrayLen: number,
  itemLen: number,
): WebAssembly.Memory => {
  const memoryLen = (arrayLen + 1) * itemLen * Uint8Array.BYTES_PER_ELEMENT;

  const pages = memoryLenToPages(memoryLen);

  return new WebAssembly.Memory({ initial: pages, maximum: pages });
};

const itemsIndexesInArray = (
  arrayLen: number,
  itemsArrayLen: number,
  itemLen: number,
): WebAssembly.Memory => {
  const memoryLen =
    (arrayLen * itemLen + itemsArrayLen * (itemLen + 1)) *
    Uint8Array.BYTES_PER_ELEMENT;

  const pages = memoryLenToPages(memoryLen);

  return new WebAssembly.Memory({ initial: pages, maximum: pages });
};

const randomBytes = (bytes: number): WebAssembly.Memory => {
  const memoryLen = bytes * Uint8Array.BYTES_PER_ELEMENT;

  const pages = memoryLenToPages(memoryLen);

  return new WebAssembly.Memory({ initial: pages, maximum: pages });
};

const randomNumberInRange = (min: number, max: number): WebAssembly.Memory => {
  const bytesNeeded = Math.ceil(Math.log2(max - min) / 8);
  const memoryLen = bytesNeeded * Uint8Array.BYTES_PER_ELEMENT;
  const pages = memoryLenToPages(memoryLen);

  return new WebAssembly.Memory({ initial: pages, maximum: pages });
};

export default {
  itemIndexInArray,
  itemsIndexesInArray,
  randomBytes,
  randomNumberInRange,
};
