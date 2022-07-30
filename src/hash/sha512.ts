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

import * as nacl from "tweetnacl";

import utils from "../utils";

import loadLibsodium from "../wasmLoaders/libsodium";

const sha512 = async (
  data: string | object | Uint8Array,
  wasm?: WebAssembly.Exports,
): Promise<Uint8Array> => {
  let array: Uint8Array;
  if (typeof data === "string") {
    if (utils.isBase64(data)) {
      array = utils.decodeFromBase64(data);
    } else {
      const dataBuffer = Buffer.from(data, "utf8");
      array = Uint8Array.from(dataBuffer);
    }
  } else if ("byteOffset" in data) {
    array = data;
  } else {
    const dataToString = JSON.stringify(data);
    const dataBuffer = Buffer.from(dataToString, "utf8");
    array = Uint8Array.from(dataBuffer);
  }
  const arrayLen = array.length;

  const memoryLen =
    (arrayLen + nacl.hash.hashLength) * Uint8Array.BYTES_PER_ELEMENT;
  wasm = wasm ? wasm : await loadLibsodium(memoryLen);
  const sha = wasm.sha512 as CallableFunction;
  const memory = wasm.memory as WebAssembly.Memory;

  let offset = 0;
  const arr = new Uint8Array(memory.buffer, offset, arrayLen);
  arr.set([...array]);

  offset += arrayLen;
  const hash = new Uint8Array(memory.buffer, offset, nacl.hash.hashLength).fill(
    0,
  );

  const result = sha(arrayLen, arr.byteOffset, hash.byteOffset) as number;

  if (result === 0) {
    return new Uint8Array([...hash]);
  } else {
    throw new Error("Could not hash the array.");
  }
};

export default sha512;
