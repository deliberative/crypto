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

import dutils from "@deliberative/utils";

import sha512 from "./sha512";

import dcryptoMemory from "./memory";

import dcryptoMethodsModule from "../c/build/dcryptoMethodsModule";

import { crypto_hash_sha512_BYTES } from "../utils/interfaces";

/**
 * Verifies that the hash was indeed included in the calculation of the Merkle root.
 * @param hash: The hash of the base element in question.
 * @param root: The Merkle root.
 * @param proofArtifacts: The first element is the first leave that was added for the calculation etc. The last
 * byte is either 0 or 1, indicating whether it is to the left or to the right in the tree.
 */
const verifyMerkleProof = async (
  hash: Uint8Array,
  root: Uint8Array,
  proofArtifacts: Uint8Array,
): Promise<boolean> => {
  if (proofArtifacts.length % (crypto_hash_sha512_BYTES + 1) !== 0)
    throw new Error("Wrong proof artifact length");

  const wasmMemory = dcryptoMemory.sha512Memory(2 * crypto_hash_sha512_BYTES);
  const wasmModule = await dcryptoMethodsModule({
    wasmMemory,
  });

  const result = new Uint8Array(crypto_hash_sha512_BYTES);
  const concatHashes = new Uint8Array(2 * crypto_hash_sha512_BYTES);

  const leavesLen = proofArtifacts.length / (crypto_hash_sha512_BYTES + 1);

  let isLeft = false;

  result.set([...hash]);
  for (let i = 0; i < leavesLen; i++) {
    const position = proofArtifacts.slice(
      i * (crypto_hash_sha512_BYTES + 1) + crypto_hash_sha512_BYTES,
      (i + 1) * (crypto_hash_sha512_BYTES + 1),
    );

    if (position[0] !== 0 && position[0] !== 1)
      throw new Error(`Wrong proofLeaves format at position ${i}`);

    isLeft = position[0] === 0;

    if (isLeft) {
      concatHashes.set([
        ...proofArtifacts.slice(
          i * (crypto_hash_sha512_BYTES + 1),
          i * (crypto_hash_sha512_BYTES + 1) + crypto_hash_sha512_BYTES,
        ),
        ...result,
      ]);
    } else {
      concatHashes.set([
        ...result,
        ...proofArtifacts.slice(
          i * (crypto_hash_sha512_BYTES + 1),
          i * (crypto_hash_sha512_BYTES + 1) + crypto_hash_sha512_BYTES,
        ),
      ]);
    }

    result.set(await sha512(concatHashes, wasmModule));
  }

  return await dutils.arraysAreEqual(result, root);
};

export default verifyMerkleProof;
