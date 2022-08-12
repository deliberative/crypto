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

import validateMnemonic from "./validateMnemonic";
import argon2 from "./argon2";

import sha512 from "../hash/sha512";

import keyPair from "../asymmetric/keyPair";

import {
  crypto_pwhash_argon2id_SALTBYTES,
  crypto_hash_sha512_BYTES,
} from "../utils/interfaces";

const keyPairFromMnemonic = async (mnemonic: string, password?: string) => {
  const isValid = await validateMnemonic(mnemonic);
  if (!isValid) throw new Error("Invalid mnemonic.");

  const defaultSalt = Uint8Array.from(Buffer.from("password12345678", "utf8"));
  const salt = new Uint8Array(crypto_pwhash_argon2id_SALTBYTES);

  if (password) {
    const pwdHash = await sha512(
      Uint8Array.from(Buffer.from(password, "utf8")),
    );

    salt.set(
      pwdHash.slice(
        crypto_hash_sha512_BYTES - crypto_pwhash_argon2id_SALTBYTES,
        crypto_hash_sha512_BYTES,
      ),
    );
  } else {
    salt.set(defaultSalt);
  }

  const seed = await argon2(mnemonic, salt);

  const keypair = await keyPair.keyPairFromSeed(seed);
  if (!keypair) throw new Error("Invalid seed from mnemonic.");

  return keypair;
};

export default keyPairFromMnemonic;
