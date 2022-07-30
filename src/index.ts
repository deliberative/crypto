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
import hash from "./hash";
import shamir from "./shamir";
import utils from "./utils";

import type { SignKeyPair } from "tweetnacl";

export interface DeliberativeCrypto {
  /**
   * Generates a 12-natural-language-word representation of an Ed25519 private key.
   */
  generateMnemonic: () => string;

  /**
   * Generates an Ed25519 keypair from a 12-natural-language-word mnemonic.
   */
  keypairFromMnemonic: (mnemonic: string) => Promise<SignKeyPair>;

  /**
   * Generates a digital signature for the message using the private key.
   */
  sign: (
    message: string | object | Uint8Array,
    mnemonicOrPrivateKey: string | Uint8Array,
  ) => Promise<Uint8Array>;

  /**
   * Verifies that the digital signature was indeed generated from private key
   * corresponding to the public key
   */
  verify: (
    message: string | object | Uint8Array,
    signature: string | Uint8Array,
    publicKey: string | Uint8Array,
  ) => Promise<boolean>;
  encrypt: (
    message: Uint8Array,
    publicKey: Uint8Array,
    additionalData: Uint8Array,
    wasm?: WebAssembly.Exports,
  ) => Promise<Uint8Array>;
  decrypt: (
    encrypted: Uint8Array,
    secretKey: Uint8Array,
    additionalData: Uint8Array,
    wasm?: WebAssembly.Exports,
  ) => Promise<Uint8Array>;

  sha512: (data: string | object | Uint8Array) => Promise<Uint8Array>;
  getMerkleRoot: (tree: Uint8Array[]) => Promise<Uint8Array>;

  /*
   * Shamir secret sharing related
   */
  splitSecret: (
    secret: Uint8Array,
    numberOfShares: number,
    threshold: number,
  ) => Promise<Uint8Array[]>;
  restoreSecret: (shares: Uint8Array[]) => Promise<Uint8Array>;

  // Utils related
  randomNumberInRange: (min: number, max: number) => Promise<number>;
  arrayRandomShuffle: <T>(array: T[]) => Promise<T[]>;
  arrayRandomSubset: <T>(array: T[], elements: number) => Promise<T[]>;
}

const dcrypto: DeliberativeCrypto = {
  generateMnemonic: asymmetric.generateMnemonic,
  keypairFromMnemonic: asymmetric.keypairFromMnemonic,
  sign: asymmetric.sign,
  verify: asymmetric.verify,
  encrypt: asymmetric.encrypt,
  decrypt: asymmetric.decrypt,

  sha512: hash.sha512,
  getMerkleRoot: hash.getMerkleRoot,

  splitSecret: shamir.splitSecret,
  restoreSecret: shamir.restoreSecret,

  randomNumberInRange: utils.randomNumberInRange,
  arrayRandomShuffle: utils.arrayRandomShuffle,
  arrayRandomSubset: utils.arrayRandomSubset,
};

export default dcrypto;
