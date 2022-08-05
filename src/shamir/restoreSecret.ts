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

import shamirMethodsModule from "../../build/shamirMethodsModule";

import type { ShamirMethodsModule } from "../../build/shamirMethodsModule";

const restoreSecret = async (
  shares: Uint8Array[],
  module?: ShamirMethodsModule,
) => {
  const sharesLen = shares.length;

  const shareItemLen = shares[0].length;
  const lengthVerification = shares.every((v) => v.length === shareItemLen);
  if (!lengthVerification) throw new Error("Shares length varies.");

  const secretLen = shareItemLen - 1;

  const wasmMemory = module
    ? module.wasmMemory
    : shamirMemory.restoreSecretMemory(secretLen, sharesLen);

  let offset = 0;
  const sharesArray = new Uint8Array(
    wasmMemory.buffer,
    offset,
    sharesLen * (secretLen + 1),
  );
  for (let i = 0; i < sharesLen; i++) {
    sharesArray.set(shares[i], i * (secretLen + 1));
  }

  offset += sharesLen * (secretLen + 1);
  const secretArray = new Uint8Array(wasmMemory.buffer, offset, secretLen);

  const shamirModule = await shamirMethodsModule({ wasmMemory });

  const result = shamirModule._restore_secret(
    sharesLen,
    secretLen,
    sharesArray.byteOffset,
    secretArray.byteOffset,
  );

  switch (result) {
    case 0: {
      return new Uint8Array([...secretArray]);
    }

    case -1: {
      throw new Error("Need at most 255 shares.");
    }

    case -2: {
      throw new Error("Not enough shares provided.");
    }

    default: {
      throw new Error("An unexpected error occured.");
    }
  }
};

export default restoreSecret;
