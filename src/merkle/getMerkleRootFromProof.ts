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

import dcryptoMethodsModule from "../c/build/dcryptoMethodsModule";

import { crypto_hash_sha512_BYTES } from "../utils/interfaces";

/**
 * @function
 * Calculates the Merkle root from the element hash and its Merkle proof.
 *
 * @param hash: The hash of the base element in question.
 * @param proof: The first element is the first leave that was added for the calculation etc. The last
 * byte is either 0 or 1, indicating whether it is to the left or to the right in the tree.
 *
 * @returns The Merkle root
 */
const getMerkleRootFromProof = async (
  hash: Uint8Array,
  proof: Uint8Array,
): Promise<Uint8Array> => {
  const proofLen = proof.length;
  if (proofLen % (crypto_hash_sha512_BYTES + 1) !== 0)
    throw new Error("Proof length not multiple of hash length + 1.");
  const proofArtifactsLen = proofLen / (crypto_hash_sha512_BYTES + 1);

  const wasmMemory = dcryptoMemory.verifyMerkleProofMemory(proofLen);
  const module = await dcryptoMethodsModule({
    wasmMemory,
  });

  const ptr1 = module._malloc(crypto_hash_sha512_BYTES);
  const elementHash = new Uint8Array(
    module.HEAPU8.buffer,
    ptr1,
    crypto_hash_sha512_BYTES,
  );
  elementHash.set(hash);

  const ptr2 = module._malloc(proofLen);
  const proofArray = new Uint8Array(module.HEAPU8.buffer, ptr2, proofLen);
  proofArray.set(proof);

  const ptr3 = module._malloc(crypto_hash_sha512_BYTES);
  const rootArray = new Uint8Array(
    module.HEAPU8.buffer,
    ptr3,
    crypto_hash_sha512_BYTES,
  );

  const result = module._get_merkle_root_from_proof(
    proofArtifactsLen,
    elementHash.byteOffset,
    proofArray.byteOffset,
    rootArray.byteOffset,
  );

  module._free(ptr1);
  module._free(ptr2);

  switch (result) {
    case 0: {
      const proof = Uint8Array.from(rootArray);
      module._free(ptr3);

      return proof;
    }

    case -1: {
      module._free(ptr3);

      throw new Error("Proof artifact position is neither left nor right.");
    }

    case -2: {
      module._free(ptr3);

      throw new Error("Could not calculate hash.");
    }

    default: {
      module._free(ptr3);

      throw new Error("Unexpected error occured.");
    }
  }
};

export default getMerkleRootFromProof;
