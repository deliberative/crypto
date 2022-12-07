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
  crypto_sign_ed25519_SECRETKEYBYTES,
  getE2EEncryptedSecretBoxEncryptedLen,
} from "../utils/interfaces";

/**
 * Function that encrypts a message with additional data using
 * the crypto_aead_chacha20poly1305_ietf_encrypt operation from
 * libsodium and computes a symmetric key Uint8Array(32) from the sender's
 * Ed25519 secret key and the receiver's Ed25519 public key.
 * The X25519 key counterparts are computed in wasm from the libsodium provided
 * crypto_sign_ed25519_pk_to_curve25519 and crypto_sign_ed25519_sk_to_curve25519
 * functions.
 * The symmetric key for encryption is then computed by crypto_kx_server_session_keys.
 * The nonce is calculated by taking the first half of the
 * sha512 hash of a Uint8Array(3 * 32) array with 32 random bytes, the X25519 public key
 * and the X25519 secret key.
 * The auth tag is generated using Poly1305.
 *
 * If you need to perform bulk encryptions with predictable message
 * and additional data sizes then it will be more efficient to preload
 * the wasm module and reuse it as follows:
 *
 * ```ts
 * const messageLen = message.length;
 * const additionalLen = additionalData.length;
 *
 * const wasmMemory = dcryptoMemory.encryptMemory(messageLen, additionalLen);
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
 * ```
 *
 * @param message - the message to encrypt
 * @param receiverPublicKey - the receiver's Ed25519 public key
 * @param senderSecretKey - the sender's Ed25519 secret key
 * @param additionalData - the additional data for aead
 * @param module - wasm module in case of bulk encryptions
 *
 * @returns Encrypted box [nonce 16 || encrypted_data || auth tag 12]
 */
const encrypt = async (
  message: Uint8Array,
  receiverPublicKey: Uint8Array,
  senderSecretKey: Uint8Array,
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
  dataArray.set(message);

  const ptr2 = dcryptoModule._malloc(crypto_sign_ed25519_PUBLICKEYBYTES);
  const pk = new Uint8Array(
    dcryptoModule.HEAP8.buffer,
    ptr2,
    crypto_sign_ed25519_PUBLICKEYBYTES,
  );
  pk.set(receiverPublicKey);

  const ptr3 = dcryptoModule._malloc(crypto_sign_ed25519_SECRETKEYBYTES);
  const sk = new Uint8Array(
    dcryptoModule.HEAP8.buffer,
    ptr3,
    crypto_sign_ed25519_SECRETKEYBYTES,
  );
  sk.set(senderSecretKey);

  const ptr4 = dcryptoModule._malloc(
    additionalLen * Uint8Array.BYTES_PER_ELEMENT,
  );
  const additional = new Uint8Array(
    dcryptoModule.HEAP8.buffer,
    ptr4,
    additionalLen * Uint8Array.BYTES_PER_ELEMENT,
  );
  additional.set(additionalData);

  const sealedBoxLen = getE2EEncryptedSecretBoxEncryptedLen(len);

  const ptr5 = dcryptoModule._malloc(
    sealedBoxLen * Uint8Array.BYTES_PER_ELEMENT,
  );
  const encrypted = new Uint8Array(
    dcryptoModule.HEAP8.buffer,
    ptr5,
    sealedBoxLen * Uint8Array.BYTES_PER_ELEMENT,
  );

  const result = dcryptoModule._e2e_encrypt_data(
    len,
    dataArray.byteOffset,
    pk.byteOffset,
    sk.byteOffset,
    additionalLen,
    additional.byteOffset,
    encrypted.byteOffset,
  );

  dcryptoModule._free(ptr1);
  dcryptoModule._free(ptr2);
  dcryptoModule._free(ptr3);
  dcryptoModule._free(ptr4);

  switch (result) {
    case 0: {
      const enc = Uint8Array.from(encrypted);
      dcryptoModule._free(ptr5);

      return enc;
    }

    case -1: {
      dcryptoModule._free(ptr5);

      throw new Error("Failed to convert Ed25519 secret key to X25519.");
    }

    case -2: {
      dcryptoModule._free(ptr5);

      throw new Error("Failed to convert Ed25519 public key to X25519.");
    }

    case -3: {
      dcryptoModule._free(ptr5);

      throw new Error("Failed to create shared secret from the sender side.");
    }

    default:
      dcryptoModule._free(ptr5);

      throw new Error("An unexpected error occured.");
  }
};

export default encrypt;
