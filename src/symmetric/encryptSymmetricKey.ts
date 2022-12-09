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
  crypto_kx_SESSIONKEYBYTES,
  getEncryptedLen,
} from "../utils/interfaces";

/**
 * Encrypts a message with additional data using
 * the crypto_aead_chacha20poly1305_ietf_encrypt operation from
 * libsodium with a precomputed symmetric key Uint8Array(32).
 * The nonce is calculated by taking the second half of the
 * sha512 hash of a Uint8Array(64) random array that is produced
 * in secure memory on wasm. The auth tag is generated using Poly1305.
 *
 * If you need to perform bulk encryptions with predictable message
 * and additional data sizes then it will be more efficient to preload
 * the wasm module and reuse it as follows:
 *
 * ```ts
 * const messageLen = message.length;
 * const additionalLen = additionalData.length;
 *
 * const wasmMemory = dcryptoMemory.encryptSymmetricKeyMemory(messageLen, additionalLen);
 * const wasmModule = await dcryptoMethodsModule({ wasmMemory });
 * ```
 *
 * If not all messages and additional data are equal, you can always just use
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
 * ```
 *
 * @param message - the message to encrypt
 * @param symmetricKey - the precomputed symmetric key
 * @param additionalData - the additional data for aead
 * @param module - wasm module in case of bulk encryptions
 *
 * @returns Encrypted box [nonce 16 || encrypted_data || auth tag 12]
 */
const encryptSymmetricKey = async (
  message: Uint8Array,
  symmetricKey: Uint8Array,
  additionalData: Uint8Array,
  module?: DCryptoMethodsModule,
): Promise<Uint8Array> => {
  const len = message.length;
  const additionalLen = additionalData.length;

  const wasmMemory = module
    ? module.wasmMemory
    : dcryptoMemory.encryptSymmetricKeyMemory(len, additionalLen);

  const dcryptoModule = module || (await dcryptoMethodsModule({ wasmMemory }));

  const ptr1 = dcryptoModule._malloc(len * Uint8Array.BYTES_PER_ELEMENT);
  const dataArray = new Uint8Array(
    dcryptoModule.HEAP8.buffer,
    ptr1,
    len * Uint8Array.BYTES_PER_ELEMENT,
  );
  dataArray.set(message);

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

  const sealedBoxLen = getEncryptedLen(len);

  const ptr4 = dcryptoModule._malloc(
    sealedBoxLen * Uint8Array.BYTES_PER_ELEMENT,
  );
  const encrypted = new Uint8Array(
    dcryptoModule.HEAP8.buffer,
    ptr4,
    sealedBoxLen * Uint8Array.BYTES_PER_ELEMENT,
  );

  const result = dcryptoModule._key_encrypt_data(
    len,
    dataArray.byteOffset,
    k.byteOffset,
    additionalLen,
    additional.byteOffset,
    encrypted.byteOffset,
  );

  dcryptoModule._free(ptr1);
  dcryptoModule._free(ptr2);
  dcryptoModule._free(ptr3);

  switch (result) {
    case 0: {
      const enc = Uint8Array.from(encrypted);
      dcryptoModule._free(ptr4);

      return enc;
    }

    default:
      dcryptoModule._free(ptr4);

      throw new Error("An unexpected error occured.");
  }
};

export default encryptSymmetricKey;
