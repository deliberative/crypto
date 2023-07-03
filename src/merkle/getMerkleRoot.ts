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
 * Returns the Merkle root of a tree.
 * If Uint8Array items' length is 64, even after serializer,
 * then we assume that it is a hash.
 *
 * @param tree: The tree.
 * @param serializer: Converts leaves into Uint8Array.
 *
 * @returns Promise<Uint8Array>
 */
const getMerkleRoot = async <T>(
  tree: (T | Uint8Array)[],
  serializer?: (i: T) => Uint8Array,
): Promise<Uint8Array> => {
  const treeLen = tree.length;
  if (treeLen === 0) {
    throw new Error("Cannot calculate Merkle root of tree with no leaves.");
  } else if (treeLen === 1) {
    const leafIsUint8Array = isUint8Array(tree[0]);
    if (!leafIsUint8Array && !serializer)
      throw new Error("Tree leaf not Uint8Array, needs serializer.");
    const leafSerialized = leafIsUint8Array
      ? (tree[0] as Uint8Array)
      : serializer
      ? serializer(tree[0] as T)
      : new Uint8Array(32); // will never happen

    return await sha512(leafSerialized);
  }

  const wasmMemory = dcryptoMemory.getMerkleRootMemory(treeLen);
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
    if (!leafIsUint8Array && !serializer)
      throw new Error("Tree leaf not Uint8Array, needs serializer.");

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
  const rootWasm = new Uint8Array(
    module.HEAPU8.buffer,
    ptr2,
    crypto_hash_sha512_BYTES,
  );

  const result = module._get_merkle_root(
    treeLen,
    leavesHashed.byteOffset,
    rootWasm.byteOffset,
  );

  module._free(ptr1);

  switch (result) {
    case 0: {
      const root = Uint8Array.from(rootWasm);
      module._free(ptr2);

      return root;
    }

    case -1: {
      module._free(ptr2);

      throw new Error("Could not calculate hash.");
    }

    default: {
      module._free(ptr2);

      throw new Error("Unexpected error occured.");
    }
  }
};

export default getMerkleRoot;
