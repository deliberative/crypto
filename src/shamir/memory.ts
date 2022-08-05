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

import memoryLenToPages from "../utils/memoryLenToPages";

const LOG_AND_EXP = 256 + 510;

const splitSecretMemory = (
  secretLen: number,
  sharesLen: number,
  threshold: number,
): WebAssembly.Memory => {
  const memoryLen =
    (sharesLen * (secretLen + 1) + secretLen + threshold + LOG_AND_EXP) *
    Uint8Array.BYTES_PER_ELEMENT;
  const pages = memoryLenToPages(memoryLen);

  return new WebAssembly.Memory({ initial: pages, maximum: pages });
};

const restoreSecretMemory = (
  secretLen: number,
  sharesLen: number,
): WebAssembly.Memory => {
  const memoryLen =
    (sharesLen * (secretLen + 1) + secretLen + 2 * sharesLen + LOG_AND_EXP) *
    Uint8Array.BYTES_PER_ELEMENT;
  const pages = memoryLenToPages(memoryLen);

  return new WebAssembly.Memory({ initial: pages, maximum: pages });
};

export default { splitSecretMemory, restoreSecretMemory };
