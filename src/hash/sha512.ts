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

import libsodiumMemory from "./memory";

import libsodiumMethodsModule from "../../build/libsodiumMethodsModule";

import type { LibsodiumMethodsModule } from "../../build/libsodiumMethodsModule";

import { crypto_hash_sha512_BYTES } from "../utils/interfaces";

const sha512 = async (
  data: Uint8Array,
  module?: LibsodiumMethodsModule,
): Promise<Uint8Array> => {
  const dataLen = data.length;

  const wasmMemory = module
    ? module.wasmMemory
    : libsodiumMemory.sha512Memory(dataLen);

  let offset = 0;
  const arr = new Uint8Array(wasmMemory.buffer, offset, dataLen);
  arr.set([...data]);

  offset += dataLen;
  const hash = new Uint8Array(
    wasmMemory.buffer,
    offset,
    crypto_hash_sha512_BYTES,
  );

  const libsodiumModule =
    module || (await libsodiumMethodsModule({ wasmMemory }));

  const result = libsodiumModule._sha512(
    dataLen,
    arr.byteOffset,
    hash.byteOffset,
  );

  if (result === 0) {
    return new Uint8Array([...hash]);
  } else {
    throw new Error("Could not hash the array.");
  }
};

export default sha512;
