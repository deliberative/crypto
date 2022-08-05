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

import libsodiumMethodsModule from "../../build/libsodiumMethodsModule";

import type { LibsodiumMethodsModule } from "../../build/libsodiumMethodsModule";

import {
  crypto_sign_ed25519_BYTES,
  crypto_sign_ed25519_PUBLICKEYBYTES,
} from "../utils/interfaces";

const verify = async (
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array,
  module?: LibsodiumMethodsModule,
): Promise<boolean> => {
  const len = message.length;

  const wasmMemory = module
    ? module.wasmMemory
    : libsodiumMemory.verifyMemory(len);

  let offset = 0;
  const dataArray = new Uint8Array(wasmMemory.buffer, offset, len);
  dataArray.set([...message]);

  offset += len;
  const sig = new Uint8Array(
    wasmMemory.buffer,
    offset,
    crypto_sign_ed25519_BYTES,
  );
  sig.set([...signature]);

  offset += crypto_sign_ed25519_BYTES;
  const key = new Uint8Array(
    wasmMemory.buffer,
    offset,
    crypto_sign_ed25519_PUBLICKEYBYTES,
  );
  key.set([...publicKey]);

  const libsodiumModule = await libsodiumMethodsModule({ wasmMemory });

  const result = libsodiumModule._verify_data(
    len,
    dataArray.byteOffset,
    sig.byteOffset,
    key.byteOffset,
  );

  return result === 0;
};

export default verify;
