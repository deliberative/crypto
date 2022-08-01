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

import loadLibsodium from "../wasmLoaders/libsodium";

import {
  crypto_box_x25519_NONCEBYTES,
  crypto_box_x25519_PUBLICKEYBYTES,
  crypto_box_x25519_SECRETKEYBYTES,
  crypto_box_poly1305_AUTHTAGBYTES,
  crypto_sign_ed25519_PUBLICKEYBYTES,
} from "../interfaces";

const encrypt = async (
  message: Uint8Array,
  publicKey: Uint8Array,
  additionalData: Uint8Array,
  wasm?: WebAssembly.Exports,
): Promise<Uint8Array> => {
  const len = message.length;
  const additionalLen = additionalData.length;

  const sealedBoxLen =
    crypto_box_x25519_PUBLICKEYBYTES + // ephemeral x25519 public key
    crypto_box_x25519_NONCEBYTES + // xchacha uses 24 byte nonce while ietf 12
    len +
    crypto_box_poly1305_AUTHTAGBYTES; // 16 bytes poly1305 auth tag

  const memoryLen =
    (len +
      crypto_sign_ed25519_PUBLICKEYBYTES +
      additionalLen +
      sealedBoxLen +
      1 * (len + crypto_box_poly1305_AUTHTAGBYTES) + // malloc'd
      2 * crypto_box_x25519_PUBLICKEYBYTES + // malloc'd
      2 * crypto_box_x25519_SECRETKEYBYTES + // malloc'd
      crypto_box_x25519_NONCEBYTES) * // malloc'd
    Uint8Array.BYTES_PER_ELEMENT;

  wasm = wasm || (await loadLibsodium(memoryLen));
  const encr = wasm.encrypt_data as CallableFunction;
  const memory = wasm.memory as WebAssembly.Memory;

  let offset = 0;
  const dataArray = new Uint8Array(memory.buffer, offset, len);
  dataArray.set([...message]);

  offset += len;
  const pub = new Uint8Array(
    memory.buffer,
    offset,
    crypto_sign_ed25519_PUBLICKEYBYTES,
  );
  pub.set([...publicKey]);

  offset += crypto_sign_ed25519_PUBLICKEYBYTES;
  const additional = new Uint8Array(memory.buffer, offset, additionalLen);
  additional.set([...additionalData]);

  offset += additionalLen;
  const encrypted = new Uint8Array(
    memory.buffer,
    offset,
    sealedBoxLen * Uint8Array.BYTES_PER_ELEMENT,
  );

  const result = encr(
    len,
    dataArray.byteOffset,
    pub.byteOffset,
    additionalLen,
    additional.byteOffset,
    encrypted.byteOffset,
  ) as number;

  switch (result) {
    case 0: {
      return encrypted;
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
