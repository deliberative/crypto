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

import arrayRandomShuffle from "./arrayRandomShuffle";

/**
 * @function
 * Random slice of an array.
 *
 * @param array: The array to get random slice from.
 * @param elements: Number of elements.
 *
 * @returns Promise<T[]>
 */
const arrayRandomSubset = async <T>(
  array: T[],
  elements: number,
): Promise<T[]> => {
  const n = array.length;

  // Sanity check
  if (n < elements || n < 2)
    throw new Error("Not enough elements in the array");

  const shuffled = await arrayRandomShuffle(array);

  return shuffled.slice(0, elements);
};

export default arrayRandomSubset;
