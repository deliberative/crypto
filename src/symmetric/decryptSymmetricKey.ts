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
  crypto_kx_SESSIONKEYBYTES,
  getDecryptedLen,
} from "../utils/interfaces";

/**
 * Function that decrypts a box with additional data using the
 * crypto_aead_chacha20poly1305_ietf_decrypt function from libsodium and
 * a provided symmetric key in Uint8Array(32) format.
 * The encrypted box is a Uint8Array[nonce 16 || encrypted_data || auth tag 12].
 *
 * If you need to perform bulk decryptions with predictable box
 * and additional data sizes then it will be more efficient to preload
 * the wasm module and reuse it as follows:
 *
 * ```ts
 * const messageLen = message.length;
 * const additionalLen = additionalData.length;
 *
 * const wasmMemory = dcryptoMemory.decryptSymmetricKeyMemory(messageLen, additionalLen);
 * const wasmModule = await dcryptoMethodsModule({ wasmMemory });
 * ```
 *
 * If not all boxes and additional data are equal, you can always just use
 * the largest Uint8Arrays as inputs.
 *
 * ```ts
 * import dcrypto from \"@deliberative/crypto\"
 *
 * const message = new Uint8Array(128).fill(1);
 * const symmetricKey = new Uint8Array(32).fill(3);
 * const additionalData = new Uint8Array(64).fill(2);
 *
 * const box = await dcrypto.encryptSymmetricKey(
 *    message,
 *    symmetricKey,
 *    additionalData
 * );
 * const decrypted = await dcrypto.decryptSymmetricKey(
 *    box,
 *    symmetricKey,
 *    additionalData
 * );
 *
 * \/\/ message should be equal to decrypted.
 * ```
 *
 * @param encrypted - the encrypted box including nonce and auth tag
 * @param symmetricKey - the precomputed symmetric key
 * @param additionalData - the additional data for aead
 * @param module - wasm module in case of bulk decryptions
 *
 * @returns The decrypted message
 */
const decryptSymmetricKey = async (
  encrypted: Uint8Array,
  symmetricKey: Uint8Array,
  additionalData: Uint8Array,
  module?: DCryptoMethodsModule,
): Promise<Uint8Array> => {
  const len = encrypted.length;
  const additionalLen = additionalData.length;

  const wasmMemory = module
    ? module.wasmMemory
    : libsodiumMemory.decryptSymmetricKeyMemory(len, additionalLen);

  const dcryptoModule = module || (await dcryptoMethodsModule({ wasmMemory }));

  const decryptedLen = getDecryptedLen(len);

  const ptr1 = dcryptoModule._malloc(len * Uint8Array.BYTES_PER_ELEMENT);
  const encryptedArray = new Uint8Array(
    dcryptoModule.HEAP8.buffer,
    ptr1,
    len * Uint8Array.BYTES_PER_ELEMENT,
  );
  encryptedArray.set(encrypted);

  const ptr2 = dcryptoModule._malloc(crypto_kx_SESSIONKEYBYTES);
  const k = new Uint8Array(
    dcryptoModule.HEAP8.buffer,
    ptr2,
    crypto_kx_SESSIONKEYBYTES,
  );
  k.set(symmetricKey);

  const ptr3 = dcryptoModule._malloc(
    additionalLen * Uint8Array.BYTES_PER_ELEMENT,
  );
  const additional = new Uint8Array(
    dcryptoModule.HEAP8.buffer,
    ptr3,
    additionalLen * Uint8Array.BYTES_PER_ELEMENT,
  );
  additional.set(additionalData);

  const ptr4 = dcryptoModule._malloc(
    decryptedLen * Uint8Array.BYTES_PER_ELEMENT,
  );
  const decrypted = new Uint8Array(
    dcryptoModule.HEAP8.buffer,
    ptr4,
    decryptedLen * Uint8Array.BYTES_PER_ELEMENT,
  );

  const result = dcryptoModule._key_decrypt_data(
    len,
    encryptedArray.byteOffset,
    k.byteOffset,
    additionalLen,
    additional.byteOffset,
    decrypted.byteOffset,
  );

  dcryptoModule._free(ptr1);
  dcryptoModule._free(ptr2);
  dcryptoModule._free(ptr3);

  switch (result) {
    case 0: {
      const decr = Uint8Array.from(decrypted);
      dcryptoModule._free(ptr4);

      return decr;
    }

    case -1: {
      dcryptoModule._free(ptr4);

      throw new Error("Unsuccessful decryption attempt");
    }

    default: {
      dcryptoModule._free(ptr4);

      throw new Error("Unexpected error occured");
    }
  }
};

export default decryptSymmetricKey;
