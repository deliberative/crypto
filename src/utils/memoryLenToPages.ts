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

/**
 * Webassembly Memory is separated into 64kb contiguous memory "pages".
 * This function takes memory length in bytes and converts it to pages.
 */
const memoryLenToPages = (
  memoryLen: number,
  minPages?: number,
  maxPages?: number,
): number => {
  minPages = minPages || 48; // 3mb // 256; // 16mb // 6; // 384kb
  maxPages = maxPages || 16384; // 1gb
  const pageSize = 64 * 1024;
  const ceil = Math.ceil(memoryLen / pageSize);
  if (ceil > maxPages)
    throw new Error(
      `Memory required is ${ceil * pageSize} bytes while declared maximum is ${
        maxPages * pageSize
      } bytes`,
    );

  return ceil < minPages ? minPages : ceil;
};

export default memoryLenToPages;
