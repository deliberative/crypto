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

import loadLibsodium from "../wasmLoaders/libsodium";

const randomBytes = async (
  n: number,
  wasm?: WebAssembly.Exports,
): Promise<Uint8Array> => {
  const memoryLen = n * Uint8Array.BYTES_PER_ELEMENT;

  wasm = wasm || (await loadLibsodium(memoryLen));
  const rnd = wasm.random_bytes as CallableFunction;
  const memory = wasm.memory as WebAssembly.Memory;

  const offset = 0;
  const bytes = new Uint8Array(memory.buffer, offset, n);

  const result = rnd(n, bytes.byteOffset) as number;

  switch (result) {
    case 0: {
      return bytes;
    }

    default: {
      throw new Error("An unexpected error occured.");
    }
  }
};

export default randomBytes;
