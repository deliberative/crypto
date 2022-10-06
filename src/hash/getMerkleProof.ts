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

/**
 * @function
 * Returns the Merkle proof of an element of a tree.
 * Can be used as a receipt of a transaction etc.
 *
 * @param tree: The tree.
 * @param element: The element.
 * @param serializer: Converts leaves into Uint8Array.
 *
 * @returns Promise<Uint8Array>
 */
const getMerkleProof = async <T extends Uint8Array | unknown>(
  tree: T[],
  element: T,
  serializer?: (i: T) => Uint8Array,
): Promise<Uint8Array> => {
  const treeLen = tree.length;
  if (treeLen === 0) {
    throw new Error("Cannot calculate Merkle proof of element of empty tree.");
  } else if (treeLen === 1) {
    throw new Error(
      "No point in calculating proof of a tree with single leaf.",
    );
  }

  const wasmMemory = dcryptoMemory.getMerkleProofMemory(treeLen);
  const module = await dcryptoMethodsModule({
    wasmMemory,
  });

  const ptr1 = module._malloc(treeLen * crypto_hash_sha512_BYTES);
  const leavesHashed = new Uint8Array(
    module.HEAP8.buffer,
    ptr1,
    treeLen * crypto_hash_sha512_BYTES,
  );

  let i = 0;
  let leafIsUint8Array = false;
  let hash: Uint8Array;
  let serialized: Uint8Array;
  for (const leaf of tree) {
    leafIsUint8Array =
      ArrayBuffer.isView(leaf) && leaf.constructor.name === "Uint8Array";
    if (!serializer && leafIsUint8Array) {
      hash = await sha512(leaf as Uint8Array, module);
      leavesHashed.set([...hash], i * crypto_hash_sha512_BYTES);
    } else if (serializer && !leafIsUint8Array) {
      serialized = serializer(leaf);
      hash = await sha512(serialized, module);
      leavesHashed.set([...hash], i * crypto_hash_sha512_BYTES);
    }
    // Cannot happen due to typeguards
    // else if (serializer && leafIsUint8Array) {
    //   throw new Error(
    //     "Did not need to provide a serializer since leaf is Uint8Array",
    //   );
    // }
    else {
      throw new Error("Tree leaf not Uint8Array, needs serializer.");
    }
    i++;
  }

  const ptr2 = module._malloc(crypto_hash_sha512_BYTES);
  const elementHash = new Uint8Array(
    module.HEAP8.buffer,
    ptr2,
    crypto_hash_sha512_BYTES,
  );
  leafIsUint8Array =
    ArrayBuffer.isView(element) && element.constructor.name === "Uint8Array";
  if (!serializer && leafIsUint8Array) {
    hash = await sha512(element as Uint8Array);
    elementHash.set([...hash]);
  } else if (serializer && !leafIsUint8Array) {
    serialized = serializer(element);
    hash = await sha512(serialized);
    elementHash.set([...hash]);
  }
  // Cannot happen due to typeguards
  // else if (serializer && leafIsUint8Array) {
  //   throw new Error(
  //     "Did not need to provide a serializer since element is Uint8Array",
  //   );
  // }
  // Cannot happen due to typeguards from tree
  // else {
  //   throw new Error("Element not Uint8Array, needs serializer.");
  // }

  const ptr3 = module._malloc(treeLen * (crypto_hash_sha512_BYTES + 1));
  const proof = new Uint8Array(
    module.HEAP8.buffer,
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
    case -1:
      module._free(ptr3);
      throw new Error("Element not in tree.");

    default: {
      const proofArray = Uint8Array.from([...proof.slice(0, result)]);
      module._free(ptr3);

      return proofArray;
    }
  }
};

export default getMerkleProof;
