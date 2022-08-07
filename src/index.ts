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
import mnemonic from "./mnemonic";
import hash from "./hash";
import shamir from "./shamir";
import utils from "./utils";

import libsodiumMethodsModule from "../build/libsodiumMethodsModule";
import shamirMethodsModule from "../build/shamirMethodsModule";
import utilsMethodsModule from "../build/utilsMethodsModule";

import type { SignKeyPair } from "./utils/interfaces";

import type { LibsodiumMethodsModule } from "../build/libsodiumMethodsModule";
import type { ShamirMethodsModule } from "../build/shamirMethodsModule";
import type { UtilsMethodsModule } from "../build/utilsMethodsModule";

export interface DeliberativeCrypto {
  /**
   * Generates a Uint8Array of size n full with random bytes
   */
  randomBytes: (
    n: number,
    module?: LibsodiumMethodsModule,
  ) => Promise<Uint8Array>;

  /**
   * Get an integer between min and max with uniform probability
   */
  randomNumberInRange: (
    min: number,
    max: number,
    module?: UtilsMethodsModule,
  ) => Promise<number>;

  /**
   * Fisher-Yates random shuffle of elements of an array
   */
  arrayRandomShuffle: <T>(array: T[]) => Promise<T[]>;

  /**
   * Fisher-Yates random shuffle then slice of array
   */
  arrayRandomSubset: <T>(array: T[], elements: number) => Promise<T[]>;

  loadUtilsMemory: {
    randomBytes: (bytes: number) => WebAssembly.Memory;
    randomNumberInRange: (min: number, max: number) => WebAssembly.Memory;
  };

  loadUtilsModule: EmscriptenModuleFactory<UtilsMethodsModule>;

  /**
   * Generate a new Ed25519 keypair
   */
  keyPair: (module?: LibsodiumMethodsModule) => Promise<SignKeyPair>;

  /**
   * Generate a new Ed25519 keypair from a given seed
   */
  keyPairFromSeed: (
    seed: Uint8Array,
    module?: LibsodiumMethodsModule,
  ) => Promise<SignKeyPair>;

  /**
   * Generate a new Ed25519 keypair from an Ed25519 secret key
   */
  keyPairFromSecretKey: (
    secretKey: Uint8Array,
    module?: LibsodiumMethodsModule,
  ) => Promise<SignKeyPair>;

  /**
   * Generates a digital signature for the message using the private key.
   */
  sign: (
    message: Uint8Array,
    secretKey: Uint8Array,
    module?: LibsodiumMethodsModule,
  ) => Promise<Uint8Array>;

  /**
   * Verifies that the digital signature was indeed generated from private key
   * corresponding to the public key
   */
  verify: (
    message: Uint8Array,
    signature: Uint8Array,
    publicKey: Uint8Array,
    module?: LibsodiumMethodsModule,
  ) => Promise<boolean>;

  /**
   * Encrypts
   */
  encrypt: (
    message: Uint8Array,
    publicKey: Uint8Array,
    additionalData: Uint8Array,
    module?: LibsodiumMethodsModule,
  ) => Promise<Uint8Array>;

  /**
   * Decrypts
   */
  decrypt: (
    encrypted: Uint8Array,
    secretKey: Uint8Array,
    additionalData: Uint8Array,
    module?: LibsodiumMethodsModule,
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
  keypairFromMnemonic: (mnemonic: string) => Promise<SignKeyPair>;

  loadAsymmetricMemory: {
    newKeyPair: () => WebAssembly.Memory;
    keyPairFromSeed: () => WebAssembly.Memory;
    keyPairFromSecretKey: () => WebAssembly.Memory;
    sign: (messageLen: number) => WebAssembly.Memory;
    verify: (messageLen: number) => WebAssembly.Memory;
    encrypt: (
      messageLen: number,
      additionalDataLen: number,
    ) => WebAssembly.Memory;
    decrypt: (
      encryptedLen: number,
      additionalDataLen: number,
    ) => WebAssembly.Memory;
  };

  loadLibsodiumModule: EmscriptenModuleFactory<LibsodiumMethodsModule>;

  sha512: (
    data: Uint8Array,
    module?: LibsodiumMethodsModule,
  ) => Promise<Uint8Array>;

  getMerkleRoot: (tree: Uint8Array[]) => Promise<Uint8Array>;

  loadHashMemory: {
    sha512: (arrayLen: number) => WebAssembly.Memory;
    merkleRoot: (maxDataLen: number) => {
      initialMemory: WebAssembly.Memory;
      subsequentMemory: WebAssembly.Memory;
    };
  };

  loadHashModule: EmscriptenModuleFactory<LibsodiumMethodsModule>;

  /*
   * Shamir secret sharing related
   */
  splitSecret: (
    secret: Uint8Array,
    numberOfShares: number,
    threshold: number,
    module?: ShamirMethodsModule,
  ) => Promise<Uint8Array[]>;

  restoreSecret: (
    shares: Uint8Array[],
    module?: ShamirMethodsModule,
  ) => Promise<Uint8Array>;

  loadShamirMemory: {
    splitSecret: (
      secretLen: number,
      sharesLen: number,
      threshold: number,
    ) => WebAssembly.Memory;
    restoreSecret: (secretLen: number, sharesLen: number) => WebAssembly.Memory;
  };

  loadShamirModule: EmscriptenModuleFactory<ShamirMethodsModule>;
}

const dcrypto: DeliberativeCrypto = {
  randomBytes: utils.randomBytes,
  randomNumberInRange: utils.randomNumberInRange,
  arrayRandomShuffle: utils.arrayRandomShuffle,
  arrayRandomSubset: utils.arrayRandomSubset,
  loadUtilsMemory: {
    randomBytes: utils.memory.randomBytesMemory,
    randomNumberInRange: utils.memory.randomNumberInRangeMemory,
  },
  loadUtilsModule: utilsMethodsModule,

  keyPair: asymmetric.keyPair.newKeyPair,
  keyPairFromSeed: asymmetric.keyPair.keyPairFromSeed,
  keyPairFromSecretKey: asymmetric.keyPair.keyPairFromSecretKey,
  sign: asymmetric.sign,
  verify: asymmetric.verify,
  encrypt: asymmetric.encrypt,
  decrypt: asymmetric.decrypt,

  generateMnemonic: mnemonic.generateMnemonic,
  validateMnemonic: mnemonic.validateMnemonic,
  keypairFromMnemonic: mnemonic.keyPairFromMnemonic,

  loadAsymmetricMemory: {
    newKeyPair: asymmetric.memory.newKeyPairMemory,
    keyPairFromSeed: asymmetric.memory.keyPairFromSeedMemory,
    keyPairFromSecretKey: asymmetric.memory.keyPairFromSecretKeyMemory,
    sign: asymmetric.memory.signMemory,
    verify: asymmetric.memory.verifyMemory,
    encrypt: asymmetric.memory.encryptMemory,
    decrypt: asymmetric.memory.decryptMemory,
  },
  loadLibsodiumModule: libsodiumMethodsModule,

  sha512: hash.sha512,
  getMerkleRoot: hash.getMerkleRoot,
  loadHashMemory: {
    sha512: hash.memory.sha512Memory,
    merkleRoot: hash.memory.merkleRootMemory,
  },
  loadHashModule: libsodiumMethodsModule,

  splitSecret: shamir.splitSecret,
  restoreSecret: shamir.restoreSecret,
  loadShamirMemory: {
    splitSecret: shamir.memory.splitSecretMemory,
    restoreSecret: shamir.memory.restoreSecretMemory,
  },
  loadShamirModule: shamirMethodsModule,
};

export default dcrypto;
