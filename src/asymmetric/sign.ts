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
import {
  crypto_sign_ed25519_BYTES,
  crypto_sign_ed25519_SECRETKEYBYTES,
} from "../utils/interfaces";

import dcryptoMethodsModule from "../c/build/dcryptoMethodsModule";

import type { DCryptoMethodsModule } from "../c/build/dcryptoMethodsModule";

/**
 * @function
 * Returns the signature of the data provided.
 */
const sign = async (
  message: Uint8Array,
  secretKey: Uint8Array,
  module?: DCryptoMethodsModule,
): Promise<Uint8Array> => {
  const messageLen = message.length;

  const wasmMemory = module
    ? module.wasmMemory
    : libsodiumMemory.signMemory(messageLen);

  let offset = 0;
  const dataArray = new Uint8Array(wasmMemory.buffer, offset, messageLen);
  dataArray.set([...message]);

  offset += messageLen;
  const signature = new Uint8Array(
    wasmMemory.buffer,
    offset,
    crypto_sign_ed25519_BYTES,
  );

  offset += crypto_sign_ed25519_BYTES;
  const sk = new Uint8Array(
    wasmMemory.buffer,
    offset,
    crypto_sign_ed25519_SECRETKEYBYTES,
  );
  sk.set([...secretKey]);

  const libsodiumModule =
    module || (await dcryptoMethodsModule({ wasmMemory }));

  libsodiumModule._sign_data(
    messageLen,
    dataArray.byteOffset,
    signature.byteOffset,
    sk.byteOffset,
  );

  return new Uint8Array([...signature]);
};

export default sign;
