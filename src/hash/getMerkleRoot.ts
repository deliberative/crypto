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

import sha512 from "./sha512";

import libsodiumMemory from "./memory";

import dcryptoMethodsModule from "../c/build/dcryptoMethodsModule";

import { crypto_hash_sha512_BYTES } from "../utils/interfaces";

const getMerkleRoot = async (tree: Uint8Array[]): Promise<Uint8Array> => {
  const treeLength = tree.length;

  const lengths = tree.map((a) => a.length);
  const maxDataLen = lengths.indexOf(Math.max(...lengths));

  const { initialMemory, subsequentMemory } =
    libsodiumMemory.merkleRootMemory(maxDataLen);

  const initialModule = await dcryptoMethodsModule({
    wasmMemory: initialMemory,
  });

  const subsequentModule = await dcryptoMethodsModule({
    wasmMemory: subsequentMemory,
  });

  const hashes: Uint8Array[] = [];
  const concatHashes = new Uint8Array(2 * crypto_hash_sha512_BYTES);

  let leaves = treeLength;
  let oddLeaves;

  while (leaves > 1) {
    oddLeaves = leaves % 2 !== 0;

    let i = 0;
    if (leaves === treeLength) {
      do {
        const hash = await sha512(tree[i++], initialModule);
        hashes.push(hash);
      } while (i < leaves);
    }

    i = 0;
    do {
      if (oddLeaves && i === leaves - 1) {
        concatHashes.set([...hashes[i * 2], ...hashes[i * 2]]);
      } else {
        concatHashes.set([...hashes[i * 2], ...hashes[i * 2 + 1]]);
      }

      const hash = await sha512(concatHashes, subsequentModule);

      hashes[i++].set([...hash]);
    } while (i * 2 + 1 < leaves);

    hashes.length = Math.ceil(hashes.length / 2);

    leaves = hashes.length;
  }

  if (hashes.length === 1) {
    return hashes[0];
  } else {
    throw new Error("Something went wrong");
  }
};

export default getMerkleRoot;
