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
 * Returns the index of an item in an array of similar items.
 *
 * @param array: The containing array.
 * @param item: The item in question.
 * @param serializer: A function converting the items into Uint8Arrays.
 * @param module: In case we want to cache the WASM loading.
 *
 * @returns Promise<number>
 */
const itemIndexInArray = async <T>(
  array: T[],
  item: T,
  serializer?: (i: T) => Uint8Array,
  module?: DCryptoMethodsModule,
): Promise<number> => {
  const arrayLen = array.length;
  if (arrayLen === 0) throw new Error("Array has length zero.");

  if (!serializer) {
    if (ArrayBuffer.isView(item) && ArrayBuffer.isView(array[0])) {
      if (!(item instanceof DataView) && !(array[0] instanceof DataView)) {
        if (
          item.constructor.name !== "Uint8Array" ||
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
    : utilsMemory.itemIndexInArray(arrayLen, crypto_hash_sha512_BYTES);

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

  for (let i = 0; i < arrayLen; i++) {
    const arraySerialized = serializer
      ? serializer(array[i])
      : (array[i] as Uint8Array);
    const hash = await sha512(arraySerialized, dcryptoHashModule);
    arr.set([...hash], i * crypto_hash_sha512_BYTES);
  }

  const ptr2 = dcryptoModule._malloc(
    crypto_hash_sha512_BYTES * Uint8Array.BYTES_PER_ELEMENT,
  );
  const itm = new Uint8Array(
    dcryptoModule.HEAP8.buffer,
    ptr2,
    crypto_hash_sha512_BYTES * Uint8Array.BYTES_PER_ELEMENT,
  );
  const itemSerialized = serializer ? serializer(item) : (item as Uint8Array);
  const itemHash = await sha512(itemSerialized, dcryptoHashModule);
  itm.set([...itemHash]);

  // Result is the index of the element in array
  const result = dcryptoModule._item_index_in_array(
    arrayLen,
    arr.byteOffset,
    itm.byteOffset,
  );

  dcryptoModule._free(ptr1);
  dcryptoModule._free(ptr2);

  return result;
};

export default itemIndexInArray;
