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

import utils from "../utils/base64";

import loadLibsodium from "../wasmLoaders/libsodium";

const verify = async (
  message: string | object | Uint8Array,
  signature: string | Uint8Array,
  publicKey: string | Uint8Array,
  wasm?: WebAssembly.Exports,
): Promise<boolean> => {
  let data: Uint8Array;
  if (typeof message === "string") {
    if (utils.isBase64(message)) {
      data = utils.decodeFromBase64(message);
    } else {
      const messageBuffer = Buffer.from(message, "utf8");
      data = Uint8Array.from(messageBuffer);
    }
  } else if ("byteOffset" in message) {
    data = message;
  } else {
    const messageString = JSON.stringify(message);
    const messageBuffer = Buffer.from(messageString, "utf8");
    data = Uint8Array.from(messageBuffer);
  }

  const len = data.length;

  const memoryLen =
    (len + nacl.sign.signatureLength + nacl.sign.publicKeyLength) *
    Uint8Array.BYTES_PER_ELEMENT;
  wasm = wasm || (await loadLibsodium(memoryLen));
  const validate = wasm.verify_data as CallableFunction;
  const memory = wasm.memory as WebAssembly.Memory;

  let offset = 0;
  const dataArray = new Uint8Array(memory.buffer, offset, len);
  dataArray.set([...data]);

  let signatureBuffer: Uint8Array;
  if (typeof signature === "string") {
    if (utils.isBase64(signature)) {
      signatureBuffer = utils.decodeFromBase64(signature);
    } else {
      signatureBuffer = Buffer.from(signature, "utf8");
    }
  } else {
    signatureBuffer = signature;
  }

  offset += len;
  const sig = new Uint8Array(memory.buffer, offset, nacl.sign.signatureLength);
  sig.set([...signatureBuffer]);

  let publicKeyBuffer: Uint8Array;
  if (typeof publicKey === "string") {
    if (utils.isBase64(publicKey)) {
      publicKeyBuffer = utils.decodeFromBase64(publicKey);
    } else {
      publicKeyBuffer = Buffer.from(publicKey, "hex");
    }
  } else {
    publicKeyBuffer = publicKey;
  }

  offset += nacl.sign.signatureLength;
  const key = new Uint8Array(memory.buffer, offset, nacl.sign.publicKeyLength);
  key.set([...publicKeyBuffer]);

  const result = validate(
    len,
    dataArray.byteOffset,
    sig.byteOffset,
    key.byteOffset,
  ) as number;

  return result === 1;
};

export default verify;
