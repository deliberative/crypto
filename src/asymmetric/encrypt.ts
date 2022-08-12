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
  crypto_box_x25519_NONCEBYTES,
  crypto_box_x25519_PUBLICKEYBYTES,
  crypto_box_poly1305_AUTHTAGBYTES,
  crypto_sign_ed25519_PUBLICKEYBYTES,
} from "../utils/interfaces";

const encrypt = async (
  message: Uint8Array,
  publicKey: Uint8Array,
  additionalData: Uint8Array,
  module?: DCryptoMethodsModule,
): Promise<Uint8Array> => {
  const len = message.length;
  const additionalLen = additionalData.length;

  const wasmMemory = module
    ? module.wasmMemory
    : libsodiumMemory.encryptMemory(len, additionalLen);

  const sealedBoxLen =
    crypto_box_x25519_PUBLICKEYBYTES + // ephemeral x25519 public key
    crypto_box_x25519_NONCEBYTES + // xchacha uses 24 byte nonce while ietf 12
    len +
    crypto_box_poly1305_AUTHTAGBYTES; // 16 bytes poly1305 auth tag

  let offset = 0;
  const dataArray = new Uint8Array(wasmMemory.buffer, offset, len);
  dataArray.set([...message]);

  offset += len;
  const pub = new Uint8Array(
    wasmMemory.buffer,
    offset,
    crypto_sign_ed25519_PUBLICKEYBYTES,
  );
  pub.set([...publicKey]);

  offset += crypto_sign_ed25519_PUBLICKEYBYTES;
  const additional = new Uint8Array(wasmMemory.buffer, offset, additionalLen);
  additional.set([...additionalData]);

  offset += additionalLen;
  const encrypted = new Uint8Array(
    wasmMemory.buffer,
    offset,
    sealedBoxLen * Uint8Array.BYTES_PER_ELEMENT,
  );

  const libsodiumModule =
    module || (await dcryptoMethodsModule({ wasmMemory }));

  const result = libsodiumModule._encrypt_data(
    len,
    dataArray.byteOffset,
    pub.byteOffset,
    additionalLen,
    additional.byteOffset,
    encrypted.byteOffset,
  );

  switch (result) {
    case 0: {
      return new Uint8Array([...encrypted]);
    }

    case -1: {
      throw new Error("Could not convert Ed25519 public key to X25519.");
    }

    case -2: {
      throw new Error("Could not create a shared secret.");
    }

    default:
      throw new Error("An unexpected error occured.");
  }
};

export default encrypt;
