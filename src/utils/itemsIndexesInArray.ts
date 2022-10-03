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
import { crypto_hash_sha512_BYTES } from "./interfaces";

import sha512 from "../hash/sha512";
import hashMemory from "../hash/memory";

import dcryptoMethodsModule from "../c/build/dcryptoMethodsModule";

import type { DCryptoMethodsModule } from "../c/build/dcryptoMethodsModule";

/**
 * @function
 * Returns an array of indexes of items in an array.
 *
 * @param array: The containing array.
 * @param items: The items in question.
 * @param serializer: Converts item to Uint8Array.
 * @param module: In case we want to cache the WASM loading.
 *
 * @returns Promise<number[]>
 */
const itemsIndexesInArray = async <T>(
  array: T[],
  items: T[],
  serializer?: (i: T) => Uint8Array,
  module?: DCryptoMethodsModule,
): Promise<number[]> => {
  const arrayLen = array.length;
  const itemsArrayLen = items.length;

  if (arrayLen === 0 || itemsArrayLen === 0) {
    throw new Error("Array and items should have at least one element each.");
  } else if (arrayLen < itemsArrayLen) {
    throw new Error("Array should be superset of items in length.");
  }

  if (!serializer) {
    if (ArrayBuffer.isView(items[0]) && ArrayBuffer.isView(array[0])) {
      if (!(items[0] instanceof DataView) && !(array[0] instanceof DataView)) {
        if (
          items[0].constructor.name !== "Uint8Array" ||
          array[0].constructor.name !== "Uint8Array"
        )
          throw new Error(
            "It is mandatory to provide a serializer for non-Uint8Array items",
          );
      } else {
        throw new Error(
          "It is mandatory to provide a serializer for non-Uint8Array items",
        );
      }
    } else {
      throw new Error(
        "It is mandatory to provide a serializer for non-Uint8Array items",
      );
    }
  }

  const wasmMemory = module
    ? module.wasmMemory
    : utilsMemory.itemsIndexesInArray(
        arrayLen,
        itemsArrayLen,
        crypto_hash_sha512_BYTES,
      );

  const dcryptoModule =
    module ||
    (await dcryptoMethodsModule({
      wasmMemory,
    }));

  const ptr1 = dcryptoModule._malloc(
    arrayLen * crypto_hash_sha512_BYTES * Uint8Array.BYTES_PER_ELEMENT,
  );
  const arr = new Uint8Array(
    dcryptoModule.HEAP8.buffer,
    ptr1,
    arrayLen * crypto_hash_sha512_BYTES * Uint8Array.BYTES_PER_ELEMENT,
  );

  const arrayItemSerialized = serializer
    ? serializer(array[0])
    : (array[0] as Uint8Array);
  const arrayItemSerializedLen = arrayItemSerialized.length;
  const hashWasmMemory = hashMemory.sha512Memory(arrayItemSerializedLen);
  const dcryptoHashModule = await dcryptoMethodsModule({
    wasmMemory: hashWasmMemory,
  });

  let i;
  for (i = 0; i < arrayLen; i++) {
    const arraySerialized = serializer
      ? serializer(array[i])
      : (array[i] as Uint8Array);
    const hash = await sha512(arraySerialized, dcryptoHashModule);
    arr.set([...hash], i * crypto_hash_sha512_BYTES);
  }

  const ptr2 = dcryptoModule._malloc(
    itemsArrayLen * crypto_hash_sha512_BYTES * Uint8Array.BYTES_PER_ELEMENT,
  );
  const itms = new Uint8Array(
    dcryptoModule.HEAP8.buffer,
    ptr2,
    itemsArrayLen * crypto_hash_sha512_BYTES * Uint8Array.BYTES_PER_ELEMENT,
  );
  for (i = 0; i < itemsArrayLen; i++) {
    const itemSerialized = serializer
      ? serializer(items[i])
      : (items[i] as Uint8Array);
    const itemHash = await sha512(itemSerialized, dcryptoHashModule);
    itms.set([...itemHash], i * crypto_hash_sha512_BYTES);
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
    if (indxs[i] >= 0) {
      indexes.push(indxs[i]);
    } else {
      if (indxs[i] === -1) {
        dcryptoModule._free(ptr3);
        throw new Error(`Item with index ${i} was not found in the array.`);
      } else if (indxs[i] === -2) {
        dcryptoModule._free(ptr3);
        throw new Error(`Item with index ${i} has a duplicate.`);
      } else {
        dcryptoModule._free(ptr3);
        throw new Error("Unexpected error occured.");
      }
    }
  }

  dcryptoModule._free(ptr3);

  return indexes;
};

export default itemsIndexesInArray;
