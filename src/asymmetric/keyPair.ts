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

import libsodiumMemory from "./memory";

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
    : libsodiumMemory.newKeyPairMemory();

  let offset = 0;
  const publicKey = new Uint8Array(
    wasmMemory.buffer,
    offset,
    crypto_sign_ed25519_PUBLICKEYBYTES,
  );

  offset += crypto_sign_ed25519_PUBLICKEYBYTES;
  const secretKey = new Uint8Array(
    wasmMemory.buffer,
    offset,
    crypto_sign_ed25519_SECRETKEYBYTES,
  );

  const libsodiumModule = await dcryptoMethodsModule({ wasmMemory });

  const result = libsodiumModule._new_keypair(
    publicKey.byteOffset,
    secretKey.byteOffset,
  );

  switch (result) {
    case 0: {
      return { publicKey, secretKey };
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
    : libsodiumMemory.keyPairFromSeedMemory();

  let offset = 0;
  const publicKey = new Uint8Array(
    wasmMemory.buffer,
    offset,
    crypto_sign_ed25519_PUBLICKEYBYTES,
  );

  offset += crypto_sign_ed25519_PUBLICKEYBYTES;
  const secretKey = new Uint8Array(
    wasmMemory.buffer,
    offset,
    crypto_sign_ed25519_SECRETKEYBYTES,
  );

  offset += crypto_sign_ed25519_SECRETKEYBYTES;
  const seedBytes = new Uint8Array(
    wasmMemory.buffer,
    offset,
    crypto_sign_ed25519_SEEDBYTES,
  );
  seedBytes.set([...seed]);

  const libsodiumModule =
    module || (await dcryptoMethodsModule({ wasmMemory }));

  const result = libsodiumModule._keypair_from_seed(
    publicKey.byteOffset,
    secretKey.byteOffset,
    seedBytes.byteOffset,
  );

  switch (result) {
    case 0: {
      return { publicKey, secretKey };
    }

    default: {
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
    : libsodiumMemory.keyPairFromSecretKeyMemory();

  let offset = 0;
  const publicKey = new Uint8Array(
    wasmMemory.buffer,
    offset,
    crypto_sign_ed25519_PUBLICKEYBYTES,
  );

  offset += crypto_sign_ed25519_PUBLICKEYBYTES;
  const sk = new Uint8Array(
    wasmMemory.buffer,
    offset,
    crypto_sign_ed25519_SECRETKEYBYTES,
  );
  sk.set([...secretKey]);

  const libsodiumModule = await dcryptoMethodsModule({ wasmMemory });

  const result = libsodiumModule._keypair_from_secret_key(
    publicKey.byteOffset,
    secretKey.byteOffset,
  );

  switch (result) {
    case 0: {
      return { publicKey, secretKey };
    }

    default: {
      throw new Error("An unexpected error occured.");
    }
  }
};

export default {
  newKeyPair,
  keyPairFromSeed,
  keyPairFromSecretKey,
};
