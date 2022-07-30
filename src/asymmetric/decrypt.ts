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

import * as nacl from "tweetnacl";

import loadLibsodium from "../wasmLoaders/libsodium";

const decrypt = async (
  encrypted: Uint8Array,
  secretKey: Uint8Array,
  additionalData: Uint8Array,
  wasm?: WebAssembly.Exports,
): Promise<Uint8Array> => {
  const len = encrypted.length;
  const additionalLen = additionalData.length;
  const decryptedLen =
    len -
    nacl.box.publicKeyLength - // x25519 ephemeral
    1 * (nacl.box.nonceLength - 12) - // nonce
    nacl.box.overheadLength; // authTag

  const memoryLen =
    (len +
      nacl.sign.secretKeyLength +
      additionalLen +
      decryptedLen +
      2 * nacl.box.publicKeyLength + // malloc'd
      1 * (nacl.box.nonceLength - 12) + // malloc'd
      nacl.box.secretKeyLength) * // malloc'd
    Uint8Array.BYTES_PER_ELEMENT;
  wasm = wasm || (await loadLibsodium(memoryLen));
  const decr = wasm.decrypt_data as CallableFunction;
  const memory = wasm.memory as WebAssembly.Memory;

  let offset = 0;
  const encryptedArray = new Uint8Array(memory.buffer, offset, len);
  encryptedArray.set([...encrypted]);

  offset += len;
  const sec = new Uint8Array(memory.buffer, offset, nacl.sign.secretKeyLength);
  sec.set([...secretKey]);

  offset += nacl.sign.secretKeyLength;
  const additional = new Uint8Array(memory.buffer, offset, additionalLen);
  additional.set([...additionalData]);

  offset += additionalLen;
  const decrypted = new Uint8Array(
    memory.buffer,
    offset,
    decryptedLen * Uint8Array.BYTES_PER_ELEMENT,
  );

  const res = decr(
    len,
    encryptedArray.byteOffset,
    sec.byteOffset,
    additionalLen,
    additional.byteOffset,
    decrypted.byteOffset,
  ) as number;

  switch (res) {
    case 0:
      return decrypted;
    case -1:
      throw new Error("Decrypted data len will be <= 0.");
    case -2:
      throw new Error("Could not create successful key exchange");
    case -3:
      throw new Error("Invalid ephemeral key signature");
    case -4:
      throw new Error("Unsuccessful decryption attempt");
    default:
      throw new Error("Unexpected error occured");
  }
};

export default decrypt;
