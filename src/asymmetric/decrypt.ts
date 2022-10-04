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

import dcryptoMethodsModule from "../c/build/dcryptoMethodsModule";

import type { DCryptoMethodsModule } from "../c/build/dcryptoMethodsModule";

import {
  crypto_sign_ed25519_SECRETKEYBYTES,
  getForwardSecretBoxDecryptedLen,
} from "../utils/interfaces";

const decrypt = async (
  encrypted: Uint8Array,
  secretKey: Uint8Array,
  additionalData: Uint8Array,
  module?: DCryptoMethodsModule,
): Promise<Uint8Array> => {
  const len = encrypted.length;
  const additionalLen = additionalData.length;

  const wasmMemory = module
    ? module.wasmMemory
    : libsodiumMemory.decryptMemory(len, additionalLen);

  const dcryptoModule = module || (await dcryptoMethodsModule({ wasmMemory }));

  const decryptedLen = getForwardSecretBoxDecryptedLen(len);

  const ptr1 = dcryptoModule._malloc(len * Uint8Array.BYTES_PER_ELEMENT);
  const encryptedArray = new Uint8Array(
    dcryptoModule.HEAP8.buffer,
    ptr1,
    len * Uint8Array.BYTES_PER_ELEMENT,
  );
  encryptedArray.set([...encrypted]);

  const ptr2 = dcryptoModule._malloc(crypto_sign_ed25519_SECRETKEYBYTES);
  const sec = new Uint8Array(
    dcryptoModule.HEAP8.buffer,
    ptr2,
    crypto_sign_ed25519_SECRETKEYBYTES,
  );
  sec.set([...secretKey]);

  const ptr3 = dcryptoModule._malloc(
    additionalLen * Uint8Array.BYTES_PER_ELEMENT,
  );
  const additional = new Uint8Array(
    dcryptoModule.HEAP8.buffer,
    ptr3,
    additionalLen * Uint8Array.BYTES_PER_ELEMENT,
  );
  additional.set([...additionalData]);

  const ptr4 = dcryptoModule._malloc(
    decryptedLen * Uint8Array.BYTES_PER_ELEMENT,
  );
  const decrypted = new Uint8Array(
    dcryptoModule.HEAP8.buffer,
    ptr4,
    decryptedLen * Uint8Array.BYTES_PER_ELEMENT,
  );

  const result = dcryptoModule._forward_secretbox_decrypt_data(
    len,
    encryptedArray.byteOffset,
    sec.byteOffset,
    additionalLen,
    additional.byteOffset,
    decrypted.byteOffset,
  );

  const decr = new Uint8Array([...decrypted]);

  dcryptoModule._free(ptr1);
  dcryptoModule._free(ptr2);
  dcryptoModule._free(ptr3);
  dcryptoModule._free(ptr4);

  switch (result) {
    case 0:
      return decr;
    case -1:
      throw new Error("Could not create successful key exchange");
    case -2:
      throw new Error("Unsuccessful decryption attempt");
    default:
      throw new Error("Unexpected error occured");
  }
};

export default decrypt;
