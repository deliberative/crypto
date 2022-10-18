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
import merkle from "./merkle";
import shamir from "./shamir";
import utils from "./utils";

import dcryptoMethodsModule from "./c/build/dcryptoMethodsModule";

const dcrypto = {
  keyPair: asymmetric.keyPair.newKeyPair,
  keyPairFromSeed: asymmetric.keyPair.keyPairFromSeed,
  keyPairFromSecretKey: asymmetric.keyPair.keyPairFromSecretKey,
  sign: asymmetric.sign,
  verify: asymmetric.verify,

  generateMnemonic: mnemonic.generateMnemonic,
  validateMnemonic: mnemonic.validateMnemonic,
  keyPairFromMnemonic: mnemonic.keyPairFromMnemonic,

  encryptForwardSecrecy: asymmetric.encrypt,
  decryptForwardSecrecy: asymmetric.decrypt,

  encryptSymmetricKey: symmetric.encrypt,
  decryptSymmetricKey: symmetric.decrypt,

  sha512: hash.sha512,
  argon2: hash.argon2,

  getMerkleRoot: merkle.getMerkleRoot,
  getMerkleProof: merkle.getMerkleProof,
  getMerkleRootFromProof: merkle.getMerkleRootFromProof,
  verifyMerkleProof: merkle.verifyMerkleProof,

  splitSecret: shamir.splitSecret,
  restoreSecret: shamir.restoreSecret,

  needleInHaystack: utils.needleInHaystack,

  randomBytes: utils.randomBytes,
  randomNumberInRange: utils.randomNumberInRange,
  arrayRandomShuffle: utils.arrayRandomShuffle,
  arrayRandomSubset: utils.arrayRandomSubset,

  getSymmetricSecretBoxEncryptedLen: utils.interfaces.getEncryptedLen,
  getSymmetricSecretBoxDecryptedLen: utils.interfaces.getDecryptedLen,
  getForwardSecretBoxEncryptedLen:
    utils.interfaces.getForwardSecretBoxEncryptedLen,
  getForwardSecretBoxDecryptedLen:
    utils.interfaces.getForwardSecretBoxDecryptedLen,

  loadWasmModule: dcryptoMethodsModule,
  loadWasmMemory: {
    newKeyPair: asymmetric.memory.newKeyPairMemory,
    keyPairFromSeed: asymmetric.memory.keyPairFromSeedMemory,
    keyPairFromSecretKey: asymmetric.memory.keyPairFromSecretKeyMemory,

    sign: asymmetric.memory.signMemory,
    verify: asymmetric.memory.verifyMemory,

    encryptForwardSecret: asymmetric.memory.encryptMemory,
    decryptForwardSecret: asymmetric.memory.decryptMemory,

    encryptSymmetricKey: symmetric.memory.encryptMemory,
    decryptSymmetricKey: symmetric.memory.decryptMemory,

    sha512: hash.memory.sha512Memory,
    argon2: hash.memory.argon2Memory,

    getMerkleRoot: merkle.memory.getMerkleRootMemory,
    getMerkleProof: merkle.memory.getMerkleProofMemory,
    verifyMerkleProof: merkle.memory.verifyMerkleProofMemory,

    splitSecret: shamir.memory.splitSecretMemory,
    restoreSecret: shamir.memory.restoreSecretMemory,

    needleInHaystack: utils.memory.needleInHaystack,

    randomBytes: utils.memory.randomBytes,
    randomNumberInRange: utils.memory.randomNumberInRange,
  },

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
};

export default dcrypto;
