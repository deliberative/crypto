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

const restoreSecret = async (
  shares: Uint8Array[],
  module?: DCryptoMethodsModule,
) => {
  const sharesLen = shares.length;

  const shareItemLen = shares[0].length;
  const lengthVerification = shares.every((v) => v.length === shareItemLen);
  if (!lengthVerification) throw new Error("Shares length varies.");

  const secretLen = shareItemLen - 1;

  const wasmMemory = module
    ? module.wasmMemory
    : shamirMemory.restoreSecretMemory(secretLen, sharesLen);

  const dcryptoModule = module || (await dcryptoMethodsModule({ wasmMemory })); // await shamirMethodsModule({ wasmMemory });

  const ptr1 = dcryptoModule._malloc(
    sharesLen * (secretLen + 1) * Uint8Array.BYTES_PER_ELEMENT,
  );
  const sharesArray = new Uint8Array(
    dcryptoModule.HEAPU8.buffer,
    ptr1,
    sharesLen * (secretLen + 1) * Uint8Array.BYTES_PER_ELEMENT,
  );
  for (let i = 0; i < sharesLen; i++) {
    sharesArray.set(shares[i], i * (secretLen + 1));
  }

  const ptr2 = dcryptoModule._malloc(secretLen * Uint8Array.BYTES_PER_ELEMENT);
  const secretArray = new Uint8Array(
    dcryptoModule.HEAPU8.buffer,
    ptr2,
    secretLen * Uint8Array.BYTES_PER_ELEMENT,
  );

  const result = dcryptoModule._restore_secret(
    sharesLen,
    secretLen,
    sharesArray.byteOffset,
    secretArray.byteOffset,
  );

  dcryptoModule._free(ptr1);

  switch (result) {
    case 0: {
      const sec = Uint8Array.from(secretArray);
      dcryptoModule._free(ptr2);

      return sec;
    }

    case -1: {
      dcryptoModule._free(ptr2);

      throw new Error("Not enough shares provided.");
    }

    case -2: {
      dcryptoModule._free(ptr2);

      throw new Error("Need at most 255 shares.");
    }

    default: {
      dcryptoModule._free(ptr2);

      throw new Error("An unexpected error occured.");
    }
  }
};

export default restoreSecret;
