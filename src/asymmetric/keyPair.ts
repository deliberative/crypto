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

import dcryptoMemory from "./memory";

import dcryptoMethodsModule from "../c/build/dcryptoMethodsModule";

import type { DCryptoMethodsModule } from "../c/build/dcryptoMethodsModule";

import {
  SignKeyPair,
  crypto_sign_ed25519_PUBLICKEYBYTES,
  crypto_sign_ed25519_SECRETKEYBYTES,
  crypto_sign_ed25519_SEEDBYTES,
} from "../utils/interfaces";

const newKeyPair = async (
  module?: DCryptoMethodsModule,
): Promise<SignKeyPair> => {
  const wasmMemory = module
    ? module.wasmMemory
    : dcryptoMemory.newKeyPairMemory();

  const dcryptoModule = await dcryptoMethodsModule({ wasmMemory });

  const ptr1 = dcryptoModule._malloc(crypto_sign_ed25519_PUBLICKEYBYTES);
  const publicKey = new Uint8Array(
    dcryptoModule.HEAP8.buffer,
    ptr1,
    crypto_sign_ed25519_PUBLICKEYBYTES,
  );

  const ptr2 = dcryptoModule._malloc(crypto_sign_ed25519_SECRETKEYBYTES);
  const secretKey = new Uint8Array(
    dcryptoModule.HEAP8.buffer,
    ptr2,
    crypto_sign_ed25519_SECRETKEYBYTES,
  );

  const result = dcryptoModule._new_keypair(
    publicKey.byteOffset,
    secretKey.byteOffset,
  );

  const keyPair = {
    publicKey: Uint8Array.from(publicKey),
    secretKey: Uint8Array.from(secretKey),
  };

  dcryptoModule._free(ptr1);
  dcryptoModule._free(ptr2);

  switch (result) {
    case 0: {
      return keyPair;
    }

    default: {
      throw new Error("An unexpected error occured.");
    }
  }
};

const keyPairFromSeed = async (
  seed: Uint8Array,
  module?: DCryptoMethodsModule,
): Promise<SignKeyPair> => {
  const wasmMemory = module
    ? module.wasmMemory
    : dcryptoMemory.keyPairFromSeedMemory();

  const dcryptoModule = module || (await dcryptoMethodsModule({ wasmMemory }));

  const ptr1 = dcryptoModule._malloc(crypto_sign_ed25519_PUBLICKEYBYTES);
  const publicKey = new Uint8Array(
    dcryptoModule.HEAP8.buffer,
    ptr1,
    crypto_sign_ed25519_PUBLICKEYBYTES,
  );

  const ptr2 = dcryptoModule._malloc(crypto_sign_ed25519_SECRETKEYBYTES);
  const secretKey = new Uint8Array(
    dcryptoModule.HEAP8.buffer,
    ptr2,
    crypto_sign_ed25519_SECRETKEYBYTES,
  );

  const ptr3 = dcryptoModule._malloc(crypto_sign_ed25519_SEEDBYTES);
  const seedBytes = new Uint8Array(
    dcryptoModule.HEAP8.buffer,
    ptr3,
    crypto_sign_ed25519_SEEDBYTES,
  );
  seedBytes.set(seed);

  const result = dcryptoModule._keypair_from_seed(
    publicKey.byteOffset,
    secretKey.byteOffset,
    seedBytes.byteOffset,
  );

  dcryptoModule._free(ptr3);

  switch (result) {
    case 0: {
      const keyPair = {
        publicKey: Uint8Array.from(publicKey),
        secretKey: Uint8Array.from(secretKey),
      };

      dcryptoModule._free(ptr1);
      dcryptoModule._free(ptr2);

      return keyPair;
    }

    default: {
      dcryptoModule._free(ptr1);
      dcryptoModule._free(ptr2);

      throw new Error("An unexpected error occured.");
    }
  }
};

const keyPairFromSecretKey = async (
  secretKey: Uint8Array,
  module?: DCryptoMethodsModule,
): Promise<SignKeyPair> => {
  const wasmMemory = module
    ? module.wasmMemory
    : dcryptoMemory.keyPairFromSecretKeyMemory();

  const dcryptoModule = await dcryptoMethodsModule({ wasmMemory });

  const ptr1 = dcryptoModule._malloc(crypto_sign_ed25519_PUBLICKEYBYTES);
  const pk = new Uint8Array(
    dcryptoModule.HEAP8.buffer,
    ptr1,
    crypto_sign_ed25519_PUBLICKEYBYTES,
  );

  const ptr2 = dcryptoModule._malloc(crypto_sign_ed25519_SECRETKEYBYTES);
  const sk = new Uint8Array(
    dcryptoModule.HEAP8.buffer,
    ptr2,
    crypto_sign_ed25519_SECRETKEYBYTES,
  );
  sk.set(secretKey);

  const result = dcryptoModule._keypair_from_secret_key(
    pk.byteOffset,
    sk.byteOffset,
  );

  dcryptoModule._free(ptr2);

  switch (result) {
    case 0: {
      const keyPair = {
        publicKey: Uint8Array.from(pk),
        secretKey,
      };

      dcryptoModule._free(ptr1);

      return keyPair;
    }

    default: {
      dcryptoModule._free(ptr1);

      throw new Error("An unexpected error occured.");
    }
  }
};

export default {
  newKeyPair,
  keyPairFromSeed,
  keyPairFromSecretKey,
};
