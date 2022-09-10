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

import dcryptoMethodsModule from "../c/build/dcryptoMethodsModule";

import type { DCryptoMethodsModule } from "../c/build/dcryptoMethodsModule";

import {
  crypto_sign_ed25519_PUBLICKEYBYTES,
  getBoxLen,
} from "../utils/interfaces";

const encrypt = async (
  message: Uint8Array,
  publicKey: Uint8Array,
  additionalData: Uint8Array,
  module?: DCryptoMethodsModule,
): Promise<Uint8Array> => {
  const len = message.length;
  const additionalLen = additionalData.length;

  const wasmMemory = module
    ? module.wasmMemory
    : dcryptoMemory.encryptMemory(len, additionalLen);

  const dcryptoModule = module || (await dcryptoMethodsModule({ wasmMemory }));

  const ptr1 = dcryptoModule._malloc(len * Uint8Array.BYTES_PER_ELEMENT);
  const dataArray = new Uint8Array(
    dcryptoModule.HEAP8.buffer,
    ptr1,
    len * Uint8Array.BYTES_PER_ELEMENT,
  );
  dataArray.set([...message]);

  const ptr2 = dcryptoModule._malloc(crypto_sign_ed25519_PUBLICKEYBYTES);
  const pub = new Uint8Array(
    dcryptoModule.HEAP8.buffer,
    ptr2,
    crypto_sign_ed25519_PUBLICKEYBYTES,
  );
  pub.set([...publicKey]);

  const ptr3 = dcryptoModule._malloc(
    additionalLen * Uint8Array.BYTES_PER_ELEMENT,
  );
  const additional = new Uint8Array(
    dcryptoModule.HEAP8.buffer,
    ptr3,
    additionalLen * Uint8Array.BYTES_PER_ELEMENT,
  );
  additional.set([...additionalData]);

  const sealedBoxLen = getBoxLen(len);

  const ptr4 = dcryptoModule._malloc(
    sealedBoxLen * Uint8Array.BYTES_PER_ELEMENT,
  );
  const encrypted = new Uint8Array(
    dcryptoModule.HEAP8.buffer,
    ptr4,
    sealedBoxLen * Uint8Array.BYTES_PER_ELEMENT,
  );

  const result = dcryptoModule._encrypt_data(
    len,
    dataArray.byteOffset,
    pub.byteOffset,
    additionalLen,
    additional.byteOffset,
    encrypted.byteOffset,
  );

  const enc = new Uint8Array([...encrypted]);

  dcryptoModule._free(ptr1);
  dcryptoModule._free(ptr2);
  dcryptoModule._free(ptr3);
  dcryptoModule._free(ptr4);

  switch (result) {
    case 0: {
      return enc;
    }

    case -1: {
      throw new Error("Could not convert Ed25519 public key to X25519.");
    }

    case -2: {
      throw new Error("Could not create a shared secret.");
    }

    default:
      throw new Error("An unexpected error occured.");
  }
};

export default encrypt;
