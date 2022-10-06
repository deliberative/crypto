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
 * Returns the Merkle root of a tree.
 * If Uint8Array items' length is 64, even after serializer,
 * then we assume that it is a hash.
 *
 * @param tree: The tree.
 * @param serializer: Converts leaves into Uint8Array.
 *
 * @returns Promise<Uint8Array>
 */
const getMerkleRoot = async <T extends Uint8Array | unknown>(
  tree: T[],
  serializer?: (i: T) => Uint8Array,
): Promise<Uint8Array> => {
  const treeLen = tree.length;
  if (treeLen === 0) {
    throw new Error("Cannot calculate Merkle root of tree with no leaves.");
  } else if (treeLen === 1) {
    const leafIsUint8Array =
      ArrayBuffer.isView(tree[0]) && tree[0].constructor.name === "Uint8Array";
    if (!serializer && leafIsUint8Array) {
      return await sha512(tree[0] as Uint8Array);
    } else if (serializer && !leafIsUint8Array) {
      const serialized = serializer(tree[0]);

      return await sha512(serialized);
    }
    // Cannot happen due to typeguards.
    // else if (serializer && leafIsUint8Array) {
    //   throw new Error(
    //     "Did not need to provide a serializer since leaf is Uint8Array",
    //   );
    // }
    else {
      throw new Error("Tree leaf not Uint8Array, needs serializer.");
    }
  }

  const wasmMemory = dcryptoMemory.getMerkleRootMemory(treeLen);
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
      // hashes.push(hash);
      leavesHashed.set([...hash], i * crypto_hash_sha512_BYTES);
    } else if (serializer && !leafIsUint8Array) {
      serialized = serializer(leaf);
      hash = await sha512(serialized, module);
      // hashes.push(hash);
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
  const rootWasm = new Uint8Array(
    module.HEAP8.buffer,
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
      const root = Uint8Array.from([...rootWasm]);
      module._free(ptr2);

      return root;
    }

    default: {
      module._free(ptr2);

      throw new Error("Unexpected error occured");
    }
  }
};

export default getMerkleRoot;
