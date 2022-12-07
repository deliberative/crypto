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

import dcryptoMemory from "./memory";
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
    : dcryptoMemory.sha512Memory(dataLen);

  const dcryptoModule = module || (await dcryptoMethodsModule({ wasmMemory }));

  const ptr1 = dcryptoModule._malloc(dataLen * Uint8Array.BYTES_PER_ELEMENT);
  const arr = new Uint8Array(
    dcryptoModule.HEAP8.buffer,
    ptr1,
    dataLen * Uint8Array.BYTES_PER_ELEMENT,
  );
  arr.set(new Uint8Array(data));

  const ptr2 = dcryptoModule._malloc(crypto_hash_sha512_BYTES);
  const hash = new Uint8Array(
    dcryptoModule.HEAP8.buffer,
    ptr2,
    crypto_hash_sha512_BYTES,
  );

  const result = dcryptoModule._sha512(
    dataLen,
    arr.byteOffset,
    hash.byteOffset,
  );

  const h = Uint8Array.from(hash);

  dcryptoModule._free(ptr1);
  dcryptoModule._free(ptr2);

  if (result === 0) return h;

  throw new Error("Could not hash the array.");
};

export default sha512;
