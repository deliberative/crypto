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

import dcryptoMemory from "./memory";

import dcryptoMethodsModule from "../c/build/dcryptoMethodsModule";

import { crypto_hash_sha512_BYTES } from "../utils/interfaces";

const getMerkleProofArtifacts = async (
  tree: Uint8Array[],
  elementIndex: number,
): Promise<Uint8Array> => {
  const treeLength = tree.length;

  const lengths = tree.map((a) => a.length);
  const maxDataLen = lengths.indexOf(Math.max(...lengths));

  const { initialMemory, subsequentMemory } =
    dcryptoMemory.merkleRootMemory(maxDataLen);

  const initialModule = await dcryptoMethodsModule({
    wasmMemory: initialMemory,
  });

  const subsequentModule = await dcryptoMethodsModule({
    wasmMemory: subsequentMemory,
  });

  const hashes: Uint8Array[] = [];
  const concatHashes = new Uint8Array(2 * crypto_hash_sha512_BYTES);

  const proofLeaves: Uint8Array[] = [];
  let indexOfInterest = elementIndex;

  let leaves = treeLength;
  let oddLeaves;

  let i;
  while (leaves > 1) {
    i = 0;
    if (leaves === treeLength) {
      do {
        const hash = await sha512(tree[i++], initialModule);
        hashes.push(hash);
      } while (i < leaves);
    }

    oddLeaves = leaves % 2 !== 0;
    i = 0;
    do {
      if (oddLeaves && i * 2 === leaves - 1) {
        concatHashes.set([...hashes[i * 2], ...hashes[i * 2]]);

        if (i === indexOfInterest) {
          proofLeaves.push(Uint8Array.from([...hashes[i], 0]));
          indexOfInterest = i;
        }
      } else {
        concatHashes.set([...hashes[i * 2], ...hashes[i * 2 + 1]]);

        if (indexOfInterest === i * 2) {
          proofLeaves.push(Uint8Array.from([...hashes[i * 2 + 1], 1]));
          indexOfInterest = i;
        } else if (indexOfInterest === i * 2 + 1) {
          proofLeaves.push(Uint8Array.from([...hashes[i * 2], 0]));
          indexOfInterest = i;
        }
      }

      const hash = await sha512(concatHashes, subsequentModule);

      hashes[i++].set([...hash]);
    } while (i * 2 + 1 < leaves);

    hashes.length = Math.ceil(hashes.length / 2);

    leaves = hashes.length;
  }

  if (hashes.length === 1) {
    const proofLeavesLen = proofLeaves.length;
    const proofArtifacts = new Uint8Array(
      proofLeavesLen * (crypto_hash_sha512_BYTES + 1),
    );

    for (i = 0; i < proofLeavesLen; i++) {
      proofArtifacts.set(proofLeaves[i], i * (crypto_hash_sha512_BYTES + 1));
    }

    return proofArtifacts;
  } else {
    throw new Error("Something went wrong");
  }
};

export default getMerkleProofArtifacts;
