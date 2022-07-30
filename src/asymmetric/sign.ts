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

import keypairFromMnemonic from "./keypairFromMnemonic";
import utils from "../utils";

import type { SignKeyPair } from "tweetnacl";

/**
 * @function
 * Returns the signature of the data provided.
 */
const sign = async (
  message: string | object | Uint8Array,
  mnemonicOrSecretKey: string | Uint8Array,
  blockAuthorSecretKey?: Uint8Array, // for ValidatorShare
): Promise<Uint8Array> => {
  let d = new Uint8Array();
  if (typeof message === "string") {
    if (utils.isBase64(message)) {
      d = utils.decodeFromBase64(message);
    } else {
      const messageBuffer = Buffer.from(message, "utf8");
      d = Uint8Array.from(messageBuffer);
    }
  } else if ("byteOffset" in message) {
    d = message;
  } else {
    // generic object
    const messageString = JSON.stringify(message);
    const messageBuffer = Buffer.from(messageString, "utf8");
    d = Uint8Array.from(messageBuffer);
  }

  const dLen = d.length;
  const extra = nacl.sign.signatureLength; // isShare ? nacl.sign.signatureLength : 0;

  let keypair: SignKeyPair;
  if (typeof mnemonicOrSecretKey === "string") {
    keypair = await keypairFromMnemonic(mnemonicOrSecretKey);
  } else {
    keypair = nacl.sign.keyPair.fromSecretKey(mnemonicOrSecretKey);
  }

  const memoryLen =
    (dLen +
      extra +
      nacl.sign.signatureLength +
      nacl.sign.secretKeyLength +
      nacl.hash.hashLength) *
    Uint8Array.BYTES_PER_ELEMENT;

  const wasm = await loadLibsodium(memoryLen);
  const signData = wasm.sign_data as CallableFunction;
  const memory = wasm.memory as WebAssembly.Memory;

  let offset = 0;
  const dataArray = new Uint8Array(memory.buffer, offset, dLen);
  dataArray.set([...d]);

  offset += dLen;
  const signature = new Uint8Array(
    memory.buffer,
    offset,
    nacl.sign.signatureLength,
  );

  offset += nacl.sign.signatureLength;
  const sk = new Uint8Array(memory.buffer, offset, nacl.sign.secretKeyLength);
  sk.set([...keypair.secretKey]);

  signData(dLen, dataArray.byteOffset, signature.byteOffset, sk.byteOffset);

  if (blockAuthorSecretKey == null) return new Uint8Array([...signature]);

  // need to sign with blockAuthorSecretKey too
  offset = 0;
  const newDataArray = new Uint8Array(memory.buffer, offset, dLen + extra);
  newDataArray.set([...d, ...signature]);

  offset += dLen + extra;
  const blockAuthorSignature = new Uint8Array(
    memory.buffer,
    offset,
    nacl.sign.signatureLength,
  );

  offset += nacl.sign.signatureLength;
  const skk = new Uint8Array(memory.buffer, offset, nacl.sign.secretKeyLength);
  skk.set([...blockAuthorSecretKey]);

  signData(
    dLen,
    dataArray.byteOffset,
    blockAuthorSignature.byteOffset,
    skk.byteOffset,
  );

  return new Uint8Array([...signature, ...blockAuthorSignature]);
};

export default sign;
