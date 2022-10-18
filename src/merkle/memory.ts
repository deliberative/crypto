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

import { crypto_hash_sha512_BYTES } from "../utils/interfaces";

const getMerkleRootMemory = (leavesLen: number): WebAssembly.Memory => {
  const memoryLen = (2 * leavesLen + 3) * crypto_hash_sha512_BYTES;
  const memoryPages = memoryLenToPages(memoryLen);

  return new WebAssembly.Memory({
    initial: memoryPages,
    maximum: memoryPages,
  });
};

const getMerkleProofMemory = (leavesLen: number): WebAssembly.Memory => {
  const memoryLen = (3 * leavesLen + 4) * crypto_hash_sha512_BYTES + leavesLen;
  const memoryPages = memoryLenToPages(memoryLen);

  return new WebAssembly.Memory({
    initial: memoryPages,
    maximum: memoryPages,
  });
};

const verifyMerkleProofMemory = (proofLen: number): WebAssembly.Memory => {
  const memoryLen = proofLen + 5 * crypto_hash_sha512_BYTES;
  const memoryPages = memoryLenToPages(memoryLen);

  return new WebAssembly.Memory({
    initial: memoryPages,
    maximum: memoryPages,
  });
};

export default {
  getMerkleRootMemory,
  getMerkleProofMemory,
  verifyMerkleProofMemory,
};
