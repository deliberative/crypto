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
  // const mnemonicBuffer = Buffer.from(mnemonicNormalized, "utf8");
  const encoder = new TextEncoder();
  const mnemonicBuffer = encoder.encode(mnemonicNormalized).buffer;
  const mnemonicInt8Array = new Int8Array(mnemonicBuffer);
  const mnemonicArrayLen = mnemonicInt8Array.length;

  salt = salt || (await randomBytes(crypto_pwhash_argon2id_SALTBYTES));

  const wasmMemory = module
    ? module.wasmMemory
    : mnemonicMemory.argon2Memory(mnemonicArrayLen);

  const dcryptoModule = module || (await dcryptoMethodsModule({ wasmMemory }));

  const ptr1 = dcryptoModule._malloc(crypto_sign_ed25519_SEEDBYTES);
  const seed = new Uint8Array(
    dcryptoModule.HEAP8.buffer,
    ptr1,
    crypto_sign_ed25519_SEEDBYTES,
  );

  const ptr2 = dcryptoModule._malloc(
    mnemonicArrayLen * Uint8Array.BYTES_PER_ELEMENT,
  );
  const mnmnc = new Int8Array(
    dcryptoModule.HEAP8.buffer,
    ptr2,
    mnemonicArrayLen * Uint8Array.BYTES_PER_ELEMENT,
  );
  mnmnc.set([...mnemonicInt8Array]);

  const ptr3 = dcryptoModule._malloc(crypto_pwhash_argon2id_SALTBYTES);
  const saltArray = new Uint8Array(
    dcryptoModule.HEAP8.buffer,
    ptr3,
    crypto_pwhash_argon2id_SALTBYTES,
  );
  saltArray.set([...salt]);

  const result = dcryptoModule._argon2(
    mnemonicArrayLen,
    seed.byteOffset,
    mnmnc.byteOffset,
    saltArray.byteOffset,
  );

  const s = new Uint8Array([...seed]);

  dcryptoModule._free(ptr1);
  dcryptoModule._free(ptr2);
  dcryptoModule._free(ptr3);

  if (result === 0) {
    return s;
  } else {
    throw new Error("Could not generate argon2id for mnemonic.");
  }
};

export default argon2;
