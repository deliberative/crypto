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

import memoryLenToPages from "../utils/memoryLenToPages";

import {
  crypto_hash_sha512_BYTES,
  crypto_kx_SESSIONKEYBYTES,
  crypto_box_x25519_NONCEBYTES,
  crypto_box_poly1305_AUTHTAGBYTES,
  getEncryptedLen,
  getDecryptedLen,
} from "../utils/interfaces";

const encryptMemory = (
  messageLen: number,
  additionalDataLen: number,
): WebAssembly.Memory => {
  const sealedBoxLen = getEncryptedLen(messageLen);
  const memoryLen =
    (messageLen +
      crypto_kx_SESSIONKEYBYTES +
      additionalDataLen +
      sealedBoxLen +
      1 * (messageLen + crypto_box_poly1305_AUTHTAGBYTES) + // malloc'd
      2 * crypto_hash_sha512_BYTES + // malloc'd
      crypto_box_x25519_NONCEBYTES) * // malloc'd
    Uint8Array.BYTES_PER_ELEMENT;
  const pages = memoryLenToPages(memoryLen);

  return new WebAssembly.Memory({ initial: pages, maximum: pages });
};

const decryptMemory = (
  encryptedLen: number,
  additionalDataLen: number,
): WebAssembly.Memory => {
  const decryptedLen = getDecryptedLen(encryptedLen);
  const memoryLen =
    (encryptedLen +
      crypto_kx_SESSIONKEYBYTES +
      additionalDataLen +
      decryptedLen +
      2 * crypto_hash_sha512_BYTES + // malloc'd
      crypto_box_x25519_NONCEBYTES) * // malloc'd
    Uint8Array.BYTES_PER_ELEMENT;
  const pages = memoryLenToPages(memoryLen);

  return new WebAssembly.Memory({ initial: pages, maximum: pages });
};

export default {
  encryptMemory,
  decryptMemory,
};
