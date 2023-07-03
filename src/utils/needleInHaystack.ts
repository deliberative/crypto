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

import utilsMemory from "./memory";
import isUint8Array from "./isUint8Array";
import { crypto_hash_sha512_BYTES } from "./interfaces";

import sha512 from "../hash/sha512";
import hashMemory from "../hash/memory";

import dcryptoMethodsModule from "../c/build/dcryptoMethodsModule";

import type { DCryptoMethodsModule } from "../c/build/dcryptoMethodsModule";

/**
 * @function
 * Returns an array of indexes of items in an array.
 * If Uint8Array items' length is 64, even after serializer,
 * then we assume that it is a hash.
 *
 * @param needles The subset array of items.
 * @param haystack The superset array.
 * @param serializer Converts item to Uint8Array.
 * @param module In case we want to cache the WASM loading.
 *
 * @returns Promise<number[]>
 */
const needleInHaystack = async <T>(
  needles: (T | Uint8Array)[],
  haystack: (T | Uint8Array)[],
  serializer?: (i: T) => Uint8Array,
  module?: DCryptoMethodsModule,
): Promise<number[]> => {
  const itemsArrayLen = needles.length;
  const arrayLen = haystack.length;

  if (arrayLen === 0 || itemsArrayLen === 0) {
    throw new Error(
      "Needles and haystack should have at least one element each.",
    );
  } else if (arrayLen < itemsArrayLen) {
    throw new Error(
      "Haystack should be superset of needles, so it should have bigger length.",
    );
  }

  const needlesAreUint8Arrays = isUint8Array(needles[0]);
  const haystackIsUint8Arrays = isUint8Array(haystack[0]);
  if (!serializer && !needlesAreUint8Arrays && !haystackIsUint8Arrays)
    throw new Error(
      "It is mandatory to provide a serializer for non-Uint8Array items",
    );

  const wasmMemory = module
    ? module.wasmMemory
    : utilsMemory.needleInHaystack(arrayLen, itemsArrayLen);

  const dcryptoModule =
    module ||
    (await dcryptoMethodsModule({
      wasmMemory,
    }));

  const ptr1 = dcryptoModule._malloc(
    arrayLen * crypto_hash_sha512_BYTES * Uint8Array.BYTES_PER_ELEMENT,
  );
  const arr = new Uint8Array(
    dcryptoModule.HEAPU8.buffer,
    ptr1,
    arrayLen * crypto_hash_sha512_BYTES * Uint8Array.BYTES_PER_ELEMENT,
  );

  const arrayItemSerialized = haystackIsUint8Arrays
    ? (haystack[0] as Uint8Array)
    : serializer
    ? serializer(haystack[0] as T)
    : new Uint8Array(32); // will never happen
  const arrayItemSerializedLen = arrayItemSerialized.length;
  const hashWasmMemory = hashMemory.sha512Memory(arrayItemSerializedLen);
  const dcryptoHashModule = await dcryptoMethodsModule({
    wasmMemory: hashWasmMemory,
  });

  let i;
  for (i = 0; i < arrayLen; i++) {
    const arraySerialized = haystackIsUint8Arrays
      ? (haystack[i] as Uint8Array)
      : serializer
      ? serializer(haystack[i] as T)
      : new Uint8Array(32); // will never happen
    const hash =
      arraySerialized.length === crypto_hash_sha512_BYTES
        ? arraySerialized
        : await sha512(arraySerialized, dcryptoHashModule);
    arr.set(hash, i * crypto_hash_sha512_BYTES);
  }

  const ptr2 = dcryptoModule._malloc(
    itemsArrayLen * crypto_hash_sha512_BYTES * Uint8Array.BYTES_PER_ELEMENT,
  );
  const itms = new Uint8Array(
    dcryptoModule.HEAPU8.buffer,
    ptr2,
    itemsArrayLen * crypto_hash_sha512_BYTES * Uint8Array.BYTES_PER_ELEMENT,
  );
  for (i = 0; i < itemsArrayLen; i++) {
    const itemSerialized = needlesAreUint8Arrays
      ? (needles[i] as Uint8Array)
      : serializer
      ? serializer(needles[i] as T)
      : new Uint8Array(32); // will never happen
    const itemHash =
      itemSerialized.length === crypto_hash_sha512_BYTES
        ? itemSerialized
        : await sha512(itemSerialized, dcryptoHashModule);
    itms.set(itemHash, i * crypto_hash_sha512_BYTES);
  }

  const ptr3 = dcryptoModule._malloc(
    itemsArrayLen * Int32Array.BYTES_PER_ELEMENT,
  );
  const indxs = new Int32Array(
    dcryptoModule.HEAP32.buffer,
    ptr3,
    itemsArrayLen * Int32Array.BYTES_PER_ELEMENT,
  );

  dcryptoModule._items_indexes_in_array(
    arrayLen,
    itemsArrayLen,
    arr.byteOffset,
    itms.byteOffset,
    indxs.byteOffset,
  );

  dcryptoModule._free(ptr1);
  dcryptoModule._free(ptr2);

  const indexes: number[] = [];
  for (i = 0; i < itemsArrayLen; i++) {
    indexes.push(indxs[i]);
  }

  dcryptoModule._free(ptr3);

  return indexes;
};

export default needleInHaystack;
