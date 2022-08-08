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
  crypto_sign_ed25519_SEEDBYTES,
  crypto_pwhash_argon2id_SALTBYTES,
} from "../utils/interfaces";

const argon2Memory = (mnemonicLen: number): WebAssembly.Memory => {
  const memoryLen =
    (75 * 1024 * 1024 +
      mnemonicLen +
      crypto_sign_ed25519_SEEDBYTES +
      crypto_pwhash_argon2id_SALTBYTES) *
    Uint8Array.BYTES_PER_ELEMENT;
  const pages = memoryLenToPages(memoryLen);

  return new WebAssembly.Memory({ initial: pages, maximum: pages });
};

export default {
  argon2Memory,
};
