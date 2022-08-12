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

import shamirMemory from "./memory";

import dcryptoMethodsModule from "../c/build/dcryptoMethodsModule";

import type { DCryptoMethodsModule } from "../c/build/dcryptoMethodsModule";

const splitSecret = async (
  secret: Uint8Array,
  sharesLen: number,
  threshold: number,
  module?: DCryptoMethodsModule,
) => {
  const secretLen = secret.length;
  if (secretLen < 2) throw new Error("Need more data.");

  const wasmMemory = module
    ? module.wasmMemory
    : shamirMemory.splitSecretMemory(secretLen, sharesLen, threshold);

  let offset = 0;
  const secretArray = new Uint8Array(wasmMemory.buffer, offset, secretLen);
  secretArray.set([...secret]);

  offset += secretLen;
  const sharesArray = new Uint8Array(
    wasmMemory.buffer,
    offset,
    sharesLen * (secretLen + 1),
  );

  const dcryptoModule = module || (await dcryptoMethodsModule({ wasmMemory })); // await shamirMethodsModule({ wasmMemory });

  const result = dcryptoModule._split_secret(
    sharesLen,
    threshold,
    secretLen,
    secretArray.byteOffset,
    sharesArray.byteOffset,
  );

  const values: Uint8Array[] = [];

  switch (result) {
    case 0: {
      for (let i = 0; i < sharesLen; i++) {
        values.push(
          sharesArray.slice(i * (secretLen + 1), (i + 1) * (secretLen + 1)),
        );
      }

      return values;
    }

    case -1: {
      throw new Error("Threshold is less than 2");
    }

    case -2: {
      throw new Error("Shares are less than threshold");
    }

    case -3: {
      throw new Error("Shares exceed 255");
    }

    default: {
      throw new Error("Unexpected error occured");
    }
  }
};

export default splitSecret;
