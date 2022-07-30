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

const restoreSecret = async (
  shares: Uint8Array[],
  wasm?: WebAssembly.Exports,
) => {
  const sharesLen = shares.length;
  if (sharesLen < 2) throw new Error("Not enough shares provided");
  if (sharesLen > 255) throw new Error(`Need at most 255 shares`);

  const shareItemLen = shares[0].length;
  const lengthVerification = shares.every((v) => v.length === shareItemLen);
  if (!lengthVerification) throw new Error("Shares length varies");

  const secretLen = shareItemLen - 1;

  const memoryLen =
    (sharesLen * (secretLen + 1) + secretLen + 2 * sharesLen) *
    Uint8Array.BYTES_PER_ELEMENT;
  wasm = wasm || (await loadShamir(memoryLen));
  const restore = wasm.restore_secret as CallableFunction;
  const memory = wasm.memory as WebAssembly.Memory;

  let offset = 0;
  const sharesArray = new Uint8Array(
    memory.buffer,
    offset,
    sharesLen * (secretLen + 1),
  );
  for (let i = 0; i < sharesLen; i++) {
    sharesArray.set(shares[i], i * (secretLen + 1));
  }

  offset += sharesLen * (secretLen + 1);
  const secretArray = new Uint8Array(memory.buffer, offset, secretLen);

  const result = restore(
    sharesLen,
    secretLen,
    sharesArray.byteOffset,
    secretArray.byteOffset,
  ) as number;

  if (result === 0) {
    return new Uint8Array([...secretArray]);
  } else if (result === -2) {
    throw new Error("Not enough shares provided.");
  } else if (result === -1) {
    throw new Error("Need at most 255 shares.");
  } else {
    throw new Error("Uncaught error.");
  }
};

export default restoreSecret;
