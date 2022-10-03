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

import asymmetric from "./asymmetric";
import symmetric from "./symmetric";
import mnemonic from "./mnemonic";
import hash from "./hash";
import shamir from "./shamir";
import utils from "./utils";

import dcryptoMethodsModule from "./c/build/dcryptoMethodsModule";

import type { SignKeyPair } from "./utils/interfaces";

import type { DCryptoMethodsModule } from "./c/build/dcryptoMethodsModule";

export interface DeliberativeCrypto {
  /**
   * Generate a new Ed25519 keypair
   */
  keyPair: (module?: DCryptoMethodsModule) => Promise<SignKeyPair>;

  /**
   * Generate a new Ed25519 keypair from a given seed
   */
  keyPairFromSeed: (
    seed: Uint8Array,
    module?: DCryptoMethodsModule,
  ) => Promise<SignKeyPair>;

  /**
   * Generate a new Ed25519 keypair from an Ed25519 secret key
   */
  keyPairFromSecretKey: (
    secretKey: Uint8Array,
    module?: DCryptoMethodsModule,
  ) => Promise<SignKeyPair>;

  /**
   * Generates a digital signature for the message using the private key.
   */
  sign: (
    message: Uint8Array,
    secretKey: Uint8Array,
    module?: DCryptoMethodsModule,
  ) => Promise<Uint8Array>;

  /**
   * Verifies that the digital signature was indeed generated from private key
   * corresponding to the public key
   */
  verify: (
    message: Uint8Array,
    signature: Uint8Array,
    publicKey: Uint8Array,
    module?: DCryptoMethodsModule,
  ) => Promise<boolean>;

  /**
   * Encrypts end-to-end with a throwaway keyPair.
   */
  encryptForwardSecrecy: (
    message: Uint8Array,
    publicKey: Uint8Array,
    additionalData: Uint8Array,
    module?: DCryptoMethodsModule,
  ) => Promise<Uint8Array>;

  /**
   * Decrypts end-to-end with the public key of a throwaway keyPair.
   */
  decryptForwardSecrecy: (
    encrypted: Uint8Array,
    secretKey: Uint8Array,
    additionalData: Uint8Array,
    module?: DCryptoMethodsModule,
  ) => Promise<Uint8Array>;

  /**
   * Generates a 12-natural-language-word representation of an Ed25519 private key.
   */
  generateMnemonic: (strength?: 128 | 160 | 192 | 224 | 256) => Promise<string>;

  /**
   * Validates that a natural-language-word representation of an Ed25519 private key is accurate
   */
  validateMnemonic: (mnemonic: string) => Promise<boolean>;

  /**
   * Generates an Ed25519 keypair from a 12-natural-language-word mnemonic.
   */
  keyPairFromMnemonic: (
    mnemonic: string,
    password?: string,
  ) => Promise<SignKeyPair>;

  /**
   * Encrypts with encryption key
   */
  encrypt: (
    message: Uint8Array,
    key: Uint8Array,
    additionalData: Uint8Array,
    module?: DCryptoMethodsModule,
  ) => Promise<Uint8Array>;

  /**
   * Decrypts with encryption key
   */
  decrypt: (
    encrypted: Uint8Array,
    key: Uint8Array,
    additionalData: Uint8Array,
    module?: DCryptoMethodsModule,
  ) => Promise<Uint8Array>;

  sha512: (
    data: Uint8Array,
    module?: DCryptoMethodsModule,
  ) => Promise<Uint8Array>;

  getMerkleRoot: (tree: Uint8Array[]) => Promise<Uint8Array>;
  getMerkleProofArtifacts: (
    tree: Uint8Array[],
    elementIndex: number,
  ) => Promise<Uint8Array>;
  verifyMerkleProof: (
    hash: Uint8Array,
    root: Uint8Array,
    leaves: Uint8Array,
  ) => Promise<boolean>;

  /*
   * Shamir secret sharing related
   */
  splitSecret: (
    secret: Uint8Array,
    numberOfShares: number,
    threshold: number,
    module?: DCryptoMethodsModule,
  ) => Promise<Uint8Array[]>;

  restoreSecret: (
    shares: Uint8Array[],
    module?: DCryptoMethodsModule,
  ) => Promise<Uint8Array>;

  constants: {
    crypto_hash_sha512_BYTES: number;
    crypto_box_poly1305_AUTHTAGBYTES: number;
    crypto_box_x25519_PUBLICKEYBYTES: number;
    crypto_box_x25519_SECRETKEYBYTES: number;
    crypto_box_x25519_NONCEBYTES: number;
    crypto_kx_SESSIONKEYBYTES: number;
    crypto_sign_ed25519_BYTES: number;
    crypto_sign_ed25519_SEEDBYTES: number;
    crypto_sign_ed25519_PUBLICKEYBYTES: number;
    crypto_sign_ed25519_SECRETKEYBYTES: number;
  };

  getSymmetricSecretBoxEncryptedLen: (messageLen: number) => number;
  getSymmetricSecretBoxDecryptedLen: (encryptedLen: number) => number;
  getForwardSecretBoxEncryptedLen: (messageLen: number) => number;
  getForwardSecretBoxDecryptedLen: (encryptedLen: number) => number;

  itemIndexInArray: <T>(
    array: T[],
    item: T,
    serializer?: (i: T) => Uint8Array,
    module?: DCryptoMethodsModule,
  ) => Promise<number>;
  itemsIndexesInArray: <T>(
    array: T[],
    items: T[],
    serializer?: (i: T) => Uint8Array,
    module?: DCryptoMethodsModule,
  ) => Promise<number[]>;

  randomBytes: (
    n: number,
    module?: DCryptoMethodsModule,
  ) => Promise<Uint8Array>;
  randomNumberInRange: (
    min: number,
    max: number,
    module?: DCryptoMethodsModule,
  ) => Promise<number>;
  arrayRandomShuffle: <T>(array: T[]) => Promise<T[]>;
  arrayRandomSubset: <T>(array: T[], elements: number) => Promise<T[]>;

  loadModule: EmscriptenModuleFactory<DCryptoMethodsModule>;
  loadWasmMemory: {
    newKeyPair: () => WebAssembly.Memory;
    keyPairFromSeed: () => WebAssembly.Memory;
    keyPairFromSecretKey: () => WebAssembly.Memory;

    sign: (messageLen: number) => WebAssembly.Memory;
    verify: (messageLen: number) => WebAssembly.Memory;

    forwardSecretEncrypt: (
      messageLen: number,
      additionalDataLen: number,
    ) => WebAssembly.Memory;
    forwardSecretDecrypt: (
      encryptedLen: number,
      additionalDataLen: number,
    ) => WebAssembly.Memory;

    symmetricKeyEncrypt: (
      messageLen: number,
      additionalDataLen: number,
    ) => WebAssembly.Memory;
    symmetricKeyDecrypt: (
      encryptedLen: number,
      additionalDataLen: number,
    ) => WebAssembly.Memory;

    sha512: (arrayLen: number) => WebAssembly.Memory;
    merkleRoot: (maxDataLen: number) => {
      initialMemory: WebAssembly.Memory;
      subsequentMemory: WebAssembly.Memory;
    };

    splitSecret: (
      secretLen: number,
      sharesLen: number,
      threshold: number,
    ) => WebAssembly.Memory;
    restoreSecret: (secretLen: number, sharesLen: number) => WebAssembly.Memory;

    itemIndexInArray: (arrayLen: number, itemLen: number) => WebAssembly.Memory;
    itemsIndexesInArray: (
      arrayLen: number,
      itemsArrayLen: number,
      itemLen: number,
    ) => WebAssembly.Memory;

    randomBytes: (bytes: number) => WebAssembly.Memory;
    randomNumberInRange: (min: number, max: number) => WebAssembly.Memory;
  };
}

const dcrypto: DeliberativeCrypto = {
  keyPair: asymmetric.keyPair.newKeyPair,
  keyPairFromSeed: asymmetric.keyPair.keyPairFromSeed,
  keyPairFromSecretKey: asymmetric.keyPair.keyPairFromSecretKey,
  sign: asymmetric.sign,
  verify: asymmetric.verify,
  encryptForwardSecrecy: asymmetric.encrypt,
  decryptForwardSecrecy: asymmetric.decrypt,

  generateMnemonic: mnemonic.generateMnemonic,
  validateMnemonic: mnemonic.validateMnemonic,
  keyPairFromMnemonic: mnemonic.keyPairFromMnemonic,

  encrypt: symmetric.encrypt,
  decrypt: symmetric.decrypt,

  sha512: hash.sha512,
  getMerkleRoot: hash.getMerkleRoot,
  getMerkleProofArtifacts: hash.getMerkleProofArtifacts,
  verifyMerkleProof: hash.verifyMerkleProof,

  splitSecret: shamir.splitSecret,
  restoreSecret: shamir.restoreSecret,

  constants: {
    crypto_hash_sha512_BYTES: utils.interfaces.crypto_hash_sha512_BYTES,
    crypto_box_poly1305_AUTHTAGBYTES:
      utils.interfaces.crypto_box_poly1305_AUTHTAGBYTES,
    crypto_box_x25519_PUBLICKEYBYTES:
      utils.interfaces.crypto_box_x25519_PUBLICKEYBYTES,
    crypto_box_x25519_SECRETKEYBYTES:
      utils.interfaces.crypto_box_x25519_SECRETKEYBYTES,
    crypto_box_x25519_NONCEBYTES: utils.interfaces.crypto_box_x25519_NONCEBYTES,
    crypto_kx_SESSIONKEYBYTES: utils.interfaces.crypto_kx_SESSIONKEYBYTES,
    crypto_sign_ed25519_BYTES: utils.interfaces.crypto_sign_ed25519_BYTES,
    crypto_sign_ed25519_SEEDBYTES:
      utils.interfaces.crypto_sign_ed25519_SEEDBYTES,
    crypto_sign_ed25519_PUBLICKEYBYTES:
      utils.interfaces.crypto_sign_ed25519_PUBLICKEYBYTES,
    crypto_sign_ed25519_SECRETKEYBYTES:
      utils.interfaces.crypto_sign_ed25519_SECRETKEYBYTES,
  },

  getSymmetricSecretBoxEncryptedLen: utils.interfaces.getEncryptedLen,
  getSymmetricSecretBoxDecryptedLen: utils.interfaces.getDecryptedLen,
  getForwardSecretBoxEncryptedLen:
    utils.interfaces.getForwardSecretBoxEncryptedLen,
  getForwardSecretBoxDecryptedLen:
    utils.interfaces.getForwardSecretBoxDecryptedLen,

  itemIndexInArray: utils.itemIndexInArray,
  itemsIndexesInArray: utils.itemsIndexesInArray,
  randomBytes: utils.randomBytes,
  randomNumberInRange: utils.randomNumberInRange,
  arrayRandomShuffle: utils.arrayRandomShuffle,
  arrayRandomSubset: utils.arrayRandomSubset,

  loadModule: dcryptoMethodsModule,
  loadWasmMemory: {
    newKeyPair: asymmetric.memory.newKeyPairMemory,
    keyPairFromSeed: asymmetric.memory.keyPairFromSeedMemory,
    keyPairFromSecretKey: asymmetric.memory.keyPairFromSecretKeyMemory,

    sign: asymmetric.memory.signMemory,
    verify: asymmetric.memory.verifyMemory,

    forwardSecretEncrypt: asymmetric.memory.encryptMemory,
    forwardSecretDecrypt: asymmetric.memory.decryptMemory,

    symmetricKeyEncrypt: symmetric.memory.encryptMemory,
    symmetricKeyDecrypt: symmetric.memory.decryptMemory,

    sha512: hash.memory.sha512Memory,
    merkleRoot: hash.memory.merkleRootMemory,

    splitSecret: shamir.memory.splitSecretMemory,
    restoreSecret: shamir.memory.restoreSecretMemory,

    itemIndexInArray: utils.memory.itemIndexInArray,
    itemsIndexesInArray: utils.memory.itemsIndexesInArray,

    randomBytes: utils.memory.randomBytes,
    randomNumberInRange: utils.memory.randomNumberInRange,
  },
};

export default dcrypto;
