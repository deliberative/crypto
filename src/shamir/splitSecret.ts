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

import loadShamir from "../wasmLoaders/shamir";

const splitSecret = async (
  secret: Uint8Array,
  sharesLen: number,
  threshold: number,
  wasm?: WebAssembly.Exports,
) => {
  const secretLen = secret.length;
  if (secretLen < 1) throw new Error("Need more data.");

  const memoryLen =
    (sharesLen * (secretLen + 1) + secretLen + threshold) *
    Uint8Array.BYTES_PER_ELEMENT;
  wasm = wasm || (await loadShamir(memoryLen));
  const split = wasm.split_secret as CallableFunction;
  const memory = wasm.memory as WebAssembly.Memory;

  let offset = 0;
  const secretArray = new Uint8Array(memory.buffer, offset, secretLen);
  secretArray.set([...secret]);

  offset += secretLen;
  const sharesArray = new Uint8Array(
    memory.buffer,
    offset,
    sharesLen * (secretLen + 1),
  );

  const result = split(
    sharesLen,
    threshold,
    secretLen,
    secretArray.byteOffset,
    sharesArray.byteOffset,
  ) as number;

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
