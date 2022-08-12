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

import mnemonicMemory from "./memory";

import randomBytes from "../utils/randomBytes";
import {
  crypto_sign_ed25519_SEEDBYTES,
  crypto_pwhash_argon2id_SALTBYTES,
} from "../utils/interfaces";

import dcryptoMethodsModule from "../c/build/dcryptoMethodsModule";

import type { DCryptoMethodsModule } from "../c/build/dcryptoMethodsModule";

const normalize = (str: string) => {
  return (str || "").normalize("NFKD");
};

const argon2 = async (
  mnemonic: string,
  salt?: Uint8Array,
  module?: DCryptoMethodsModule,
): Promise<Uint8Array> => {
  const mnemonicNormalized = normalize(mnemonic);
  const mnemonicBuffer = Buffer.from(mnemonicNormalized, "utf8");
  const mnemonicInt8Array = Int8Array.from(mnemonicBuffer);
  const mnemonicArrayLen = mnemonicInt8Array.length;

  salt = salt || (await randomBytes(crypto_pwhash_argon2id_SALTBYTES));

  const wasmMemory = module
    ? module.wasmMemory
    : mnemonicMemory.argon2Memory(mnemonicArrayLen);

  let offset = 0;
  const seed = new Uint8Array(
    wasmMemory.buffer,
    offset,
    crypto_sign_ed25519_SEEDBYTES,
  );

  offset += crypto_sign_ed25519_SEEDBYTES;
  const mnmnc = new Int8Array(wasmMemory.buffer, offset, mnemonicArrayLen);
  mnmnc.set([...mnemonicInt8Array]);

  offset += mnemonicArrayLen;
  const saltArray = new Uint8Array(
    wasmMemory.buffer,
    offset,
    crypto_pwhash_argon2id_SALTBYTES,
  );
  saltArray.set([...salt]);

  const dcryptoModule = module || (await dcryptoMethodsModule({ wasmMemory }));

  const result = dcryptoModule._argon2(
    mnemonicArrayLen,
    seed.byteOffset,
    mnmnc.byteOffset,
    saltArray.byteOffset,
  );

  if (result === 0) {
    return new Uint8Array([...seed]);
  } else {
    throw new Error("Could not generate argon2id for mnemonic.");
  }
};

export default argon2;
