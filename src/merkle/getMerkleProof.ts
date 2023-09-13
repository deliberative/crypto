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

import dcryptoMemory from "./memory";

import sha512 from "../hash/sha512";
import isUint8Array from "../utils/isUint8Array";

import dcryptoMethodsModule from "../c/build/dcryptoMethodsModule";

import { crypto_hash_sha512_BYTES } from "../utils/interfaces";

/**
 * @function
 * getMerkleProof
 *
 * @description
 * Returns the Merkle proof of an element of a tree.
 * Can be used as a receipt of a transaction etc.
 *
 * @param {(T | Uint8Array)[]} tree: The tree.
 * @param {T | Uint8Array} element: The element.
 * @param {(i: T) => Uint8Array} serializer?: Converts leaves into Uint8Array.
 *
 * @returns {Promise<Uint8Array>}: The Merkle proof.
 */
const getMerkleProof = async <T>(
  tree: (T | Uint8Array)[],
  element: T | Uint8Array,
  serializer?: (i: T) => Uint8Array,
): Promise<Uint8Array> => {
  const treeLen = tree.length;
  if (treeLen === 0) {
    throw new Error("Cannot calculate Merkle proof of element of empty tree.");
  } else if (treeLen === 1) {
    // "No point in calculating proof of a tree with single leaf.",
    return new Uint8Array(crypto_hash_sha512_BYTES + 1).fill(1);
  }

  const leavesAreUint8Arrays = isUint8Array(tree[0]);
  const elementIsUint8Array = isUint8Array(element);
  if (!serializer && (!leavesAreUint8Arrays || !elementIsUint8Array))
    throw new Error(
      "It is mandatory to provide a serializer for non-Uint8Array items",
    );

  const wasmMemory = dcryptoMemory.getMerkleProofMemory(treeLen);
  const module = await dcryptoMethodsModule({
    wasmMemory,
  });

  const ptr1 = module._malloc(treeLen * crypto_hash_sha512_BYTES);
  const leavesHashed = new Uint8Array(
    module.HEAPU8.buffer,
    ptr1,
    treeLen * crypto_hash_sha512_BYTES,
  );

  let i = 0;
  let leafIsUint8Array = false;
  let hash: Uint8Array;
  let serialized: Uint8Array;
  let leaf: T | Uint8Array;
  for (let j = 0; j < treeLen; j++) {
    leaf = tree[i];
    leafIsUint8Array = isUint8Array(leaf);
    serialized = leafIsUint8Array
      ? (leaf as Uint8Array)
      : serializer
      ? serializer(leaf as T)
      : new Uint8Array(32); // will never happen
    hash = await sha512(serialized, module);
    leavesHashed.set(hash, i * crypto_hash_sha512_BYTES);
    i++;
  }

  const ptr2 = module._malloc(crypto_hash_sha512_BYTES);
  const elementHash = new Uint8Array(
    module.HEAPU8.buffer,
    ptr2,
    crypto_hash_sha512_BYTES,
  );
  const elementSerialized = elementIsUint8Array
    ? element
    : serializer
    ? serializer(element)
    : new Uint8Array(32); // will never happen
  hash = await sha512(elementSerialized);
  elementHash.set(hash);

  const ptr3 = module._malloc(treeLen * (crypto_hash_sha512_BYTES + 1));
  const proof = new Uint8Array(
    module.HEAPU8.buffer,
    ptr3,
    treeLen * (crypto_hash_sha512_BYTES + 1),
  );

  const result = module._get_merkle_proof(
    treeLen,
    leavesHashed.byteOffset,
    elementHash.byteOffset,
    proof.byteOffset,
  );

  module._free(ptr1);
  module._free(ptr2);

  switch (result) {
    case -1: {
      module._free(ptr3);

      throw new Error("Element not in tree.");
    }

    case -2: {
      module._free(ptr3);

      throw new Error("Could not allocate memory for hashes helper array.");
    }

    case -3: {
      module._free(ptr3);

      throw new Error(
        "Could not allocate memory for hash concatenation helper array.",
      );
    }

    case -4: {
      module._free(ptr3);

      throw new Error("Could not calculate hash.");
    }

    default: {
      const proofArray = Uint8Array.from(proof.slice(0, result));
      module._free(ptr3);

      return proofArray;
    }
  }
};

export default getMerkleProof;
