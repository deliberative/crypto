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

import dcryptoMethodsModule from "../c/build/dcryptoMethodsModule";

import type { DCryptoMethodsModule } from "../c/build/dcryptoMethodsModule";

const randomBytes = async (
  n: number,
  module?: DCryptoMethodsModule,
): Promise<Uint8Array> => {
  const wasmMemory = module
    ? module.wasmMemory
    : utilsMemory.randomBytesMemory(n);

  const bytes = new Uint8Array(wasmMemory.buffer, 0, n);

  const dcryptoModule =
    module ||
    (await dcryptoMethodsModule({
      wasmMemory,
    }));

  const result = dcryptoModule._random_bytes(n, bytes.byteOffset);

  if (result === 0) return new Uint8Array([...bytes]);

  throw new Error("Could not generate random data");
};

export default randomBytes;
