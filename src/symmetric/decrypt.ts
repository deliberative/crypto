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
  crypto_sign_ed25519_PUBLICKEYBYTES,
  crypto_sign_ed25519_SECRETKEYBYTES,
  getDecryptedLen,
} from "../utils/interfaces";

/**
 * Decrypts a box with additional data using the
 * crypto_aead_chacha20poly1305_ietf_decrypt function from libsodium and
 * computes a symmetric key Uint8Array(32) from the sender's
 * Ed25519 public key and the receiver's Ed25519 secret key.
 * The X25519 key counterparts are computed in wasm from the libsodium provided
 * crypto_sign_ed25519_pk_to_curve25519 and crypto_sign_ed25519_sk_to_curve25519
 * functions.
 * The symmetric key for encryption is then computed by crypto_kx_client_session_keys.
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
 * const wasmMemory = dcryptoMemory.decryptMemory(messageLen, additionalLen);
 * const wasmModule = await dcryptoMethodsModule({ wasmMemory });
 * ```
 *
 * If not all boxes and additional data are equal, you can always just use
 * the largest Uint8Arrays as inputs.
 *
 * @example
 * ```ts
 * import dcrypto from \"@deliberative/crypto\"
 *
 * const message = new Uint8Array(128).fill(1);
 * const additionalData = new Uint8Array(64).fill(2);
 *
 * const aliceKeyPair = await dcrypto.keyPair();
 * const bobKeyPair = await dcrypto.keyPair();
 *
 * const box = await dcrypto.encrypt(
 *    message,
 *    bobKeyPair.publicKey,
 *    aliceKeyPair.secretKey,
 *    additionalData
 * );
 *
 * const decrypted = await dcrypto.decrypt(
 *    box,
 *    aliceKeyPair.publicKey,
 *    bobKeyPair.secretKey,
 *    additionalData
 * );
 *
 * \/\/ message should be equal to decrypted.
 * ```
 *
 * @param encrypted - The encrypted box including nonce and auth tag
 * @param senderPublicKey - The sender public key
 * @param receiverSecretKey - The receiver secret key
 * @param additionalData - The additional data for aead
 * @param module - The wasm module in case of bulk decryptions
 * @returns The decrypted message
 */
const decrypt = async (
  encrypted: Uint8Array,
  senderPublicKey: Uint8Array,
  receiverSecretKey: Uint8Array,
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
    dcryptoModule.HEAPU8.buffer,
    ptr1,
    len * Uint8Array.BYTES_PER_ELEMENT,
  );
  encryptedArray.set(encrypted);

  const ptr2 = dcryptoModule._malloc(crypto_sign_ed25519_PUBLICKEYBYTES);
  const pk = new Uint8Array(
    dcryptoModule.HEAPU8.buffer,
    ptr2,
    crypto_sign_ed25519_PUBLICKEYBYTES,
  );
  pk.set(senderPublicKey);

  const ptr3 = dcryptoModule._malloc(crypto_sign_ed25519_SECRETKEYBYTES);
  const sk = new Uint8Array(
    dcryptoModule.HEAPU8.buffer,
    ptr3,
    crypto_sign_ed25519_SECRETKEYBYTES,
  );
  sk.set(receiverSecretKey);

  const ptr4 = dcryptoModule._malloc(
    additionalLen * Uint8Array.BYTES_PER_ELEMENT,
  );
  const additional = new Uint8Array(
    dcryptoModule.HEAPU8.buffer,
    ptr4,
    additionalLen * Uint8Array.BYTES_PER_ELEMENT,
  );
  additional.set(additionalData);

  const ptr5 = dcryptoModule._malloc(
    decryptedLen * Uint8Array.BYTES_PER_ELEMENT,
  );
  const decrypted = new Uint8Array(
    dcryptoModule.HEAPU8.buffer,
    ptr5,
    decryptedLen * Uint8Array.BYTES_PER_ELEMENT,
  );

  const result = dcryptoModule._e2e_decrypt_data(
    len,
    encryptedArray.byteOffset,
    pk.byteOffset,
    sk.byteOffset,
    additionalLen,
    additional.byteOffset,
    decrypted.byteOffset,
  );

  dcryptoModule._free(ptr1);
  dcryptoModule._free(ptr2);
  dcryptoModule._free(ptr3);
  dcryptoModule._free(ptr4);

  switch (result) {
    case 0: {
      const decr = Uint8Array.from(decrypted);
      dcryptoModule._free(ptr5);

      return decr;
    }

    case -1: {
      dcryptoModule._free(ptr5);

      throw new Error("Unsuccessful decryption attempt");
    }

    default: {
      dcryptoModule._free(ptr5);

      throw new Error("Unexpected error occured");
    }
  }
};

export default decrypt;
