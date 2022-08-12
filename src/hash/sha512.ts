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
import { crypto_hash_sha512_BYTES } from "../utils/interfaces";

import dcryptoMethodsModule from "../c/build/dcryptoMethodsModule";

import type { DCryptoMethodsModule } from "../c/build/dcryptoMethodsModule";

const sha512 = async (
  data: Uint8Array,
  module?: DCryptoMethodsModule,
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

  const dcryptoModule = module || (await dcryptoMethodsModule({ wasmMemory }));

  const result = dcryptoModule._sha512(
    dataLen,
    arr.byteOffset,
    hash.byteOffset,
  );

  if (result === 0) return new Uint8Array([...hash]);

  throw new Error("Could not hash the array.");
};

export default sha512;
