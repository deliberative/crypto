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
import {
  crypto_sign_ed25519_BYTES,
  crypto_sign_ed25519_PUBLICKEYBYTES,
} from "../utils/interfaces";

import dcryptoMethodsModule from "../c/build/dcryptoMethodsModule";

import type { DCryptoMethodsModule } from "../c/build/dcryptoMethodsModule";

const verify = async (
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array,
  module?: DCryptoMethodsModule,
): Promise<boolean> => {
  const len = message.length;

  const wasmMemory = module
    ? module.wasmMemory
    : dcryptoMemory.verifyMemory(len);

  const dcryptoModule = module || (await dcryptoMethodsModule({ wasmMemory }));

  const ptr1 = dcryptoModule._malloc(len * Uint8Array.BYTES_PER_ELEMENT);
  const dataArray = new Uint8Array(
    dcryptoModule.HEAPU8.buffer,
    ptr1,
    len * Uint8Array.BYTES_PER_ELEMENT,
  );
  dataArray.set(message);

  const ptr2 = dcryptoModule._malloc(crypto_sign_ed25519_BYTES);
  const sig = new Uint8Array(
    dcryptoModule.HEAPU8.buffer,
    ptr2,
    crypto_sign_ed25519_BYTES,
  );
  sig.set(signature);

  const ptr3 = dcryptoModule._malloc(crypto_sign_ed25519_PUBLICKEYBYTES);
  const key = new Uint8Array(
    dcryptoModule.HEAPU8.buffer,
    ptr3,
    crypto_sign_ed25519_PUBLICKEYBYTES,
  );
  key.set(publicKey);

  const result = dcryptoModule._verify_data(
    len,
    dataArray.byteOffset,
    sig.byteOffset,
    key.byteOffset,
  );

  dcryptoModule._free(ptr1);
  dcryptoModule._free(ptr2);
  dcryptoModule._free(ptr3);

  return result === 0;
};

export default verify;
