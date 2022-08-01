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

import * as bip39 from "bip39";

import randomBytes from "./randomBytes";

import loadLibsodium from "../wasmLoaders/libsodium";

import {
  SignKeyPair,
  crypto_sign_ed25519_PUBLICKEYBYTES,
  crypto_sign_ed25519_SECRETKEYBYTES,
  crypto_sign_ed25519_SEEDBYTES,
} from "../interfaces";

const newKeyPair = async (wasm?: WebAssembly.Exports): Promise<SignKeyPair> => {
  const memoryLen =
    (crypto_sign_ed25519_PUBLICKEYBYTES + crypto_sign_ed25519_SECRETKEYBYTES) *
    Uint8Array.BYTES_PER_ELEMENT;

  wasm = wasm || (await loadLibsodium(memoryLen));
  const kpr = wasm.new_keypair as CallableFunction;
  const memory = wasm.memory as WebAssembly.Memory;

  let offset = 0;
  const publicKey = new Uint8Array(
    memory.buffer,
    offset,
    crypto_sign_ed25519_PUBLICKEYBYTES,
  );

  offset += crypto_sign_ed25519_PUBLICKEYBYTES;
  const secretKey = new Uint8Array(
    memory.buffer,
    offset,
    crypto_sign_ed25519_SECRETKEYBYTES,
  );

  const result = kpr(publicKey.byteOffset, secretKey.byteOffset) as number;

  switch (result) {
    case 0: {
      return { publicKey, secretKey };
    }

    default: {
      throw new Error("An unexpected error occured.");
    }
  }
};

const generateMnemonic = async () => {
  const seed = await randomBytes(crypto_sign_ed25519_SEEDBYTES);
  const seedBuffer = Buffer.from(
    seed,
    seed.byteOffset,
    crypto_sign_ed25519_SEEDBYTES,
  );

  return bip39.entropyToMnemonic(seedBuffer);
};

const keyPairFromSeed = async (
  seed: Uint8Array,
  wasm?: WebAssembly.Exports,
): Promise<SignKeyPair> => {
  const memoryLen =
    (crypto_sign_ed25519_PUBLICKEYBYTES +
      crypto_sign_ed25519_SECRETKEYBYTES +
      crypto_sign_ed25519_SEEDBYTES) *
    Uint8Array.BYTES_PER_ELEMENT;

  wasm = wasm || (await loadLibsodium(memoryLen));
  const kprFrmSeed = wasm.keypair_from_seed as CallableFunction;
  const memory = wasm.memory as WebAssembly.Memory;

  let offset = 0;
  const publicKey = new Uint8Array(
    memory.buffer,
    offset,
    crypto_sign_ed25519_PUBLICKEYBYTES,
  );

  offset += crypto_sign_ed25519_PUBLICKEYBYTES;
  const secretKey = new Uint8Array(
    memory.buffer,
    offset,
    crypto_sign_ed25519_SECRETKEYBYTES,
  );

  offset += crypto_sign_ed25519_SECRETKEYBYTES;
  const seedBytes = new Uint8Array(
    memory.buffer,
    offset,
    crypto_sign_ed25519_SEEDBYTES,
  );
  seedBytes.set([...seed]);

  const result = kprFrmSeed(
    publicKey.byteOffset,
    secretKey.byteOffset,
    seedBytes.byteOffset,
  ) as number;

  switch (result) {
    case 0: {
      return { publicKey, secretKey };
    }

    default: {
      throw new Error("An unexpected error occured.");
    }
  }
};

const keyPairFromMnemonic = async (mnemonic: string) => {
  const isValid = bip39.validateMnemonic(mnemonic);
  if (!isValid) throw new Error("Invalid mnemonic.");

  const seed = await bip39.mnemonicToSeed(mnemonic);
  const privateKeySeed = new Uint8Array(seed.toJSON().data.slice(0, 32));
  const keypair = await keyPairFromSeed(privateKeySeed);
  if (!keypair) throw new Error("Invalid seed from mnemonic.");

  return keypair;
};

const keyPairFromSecretKey = async (
  secretKey: Uint8Array,
  wasm?: WebAssembly.Exports,
): Promise<SignKeyPair> => {
  const memoryLen =
    (crypto_sign_ed25519_PUBLICKEYBYTES + crypto_sign_ed25519_SECRETKEYBYTES) *
    Uint8Array.BYTES_PER_ELEMENT;

  wasm = wasm || (await loadLibsodium(memoryLen));
  const kpr = wasm.keypair_from_secret_key as CallableFunction;
  const memory = wasm.memory as WebAssembly.Memory;

  let offset = 0;
  const publicKey = new Uint8Array(
    memory.buffer,
    offset,
    crypto_sign_ed25519_PUBLICKEYBYTES,
  );

  offset += crypto_sign_ed25519_PUBLICKEYBYTES;
  const sk = new Uint8Array(
    memory.buffer,
    offset,
    crypto_sign_ed25519_SECRETKEYBYTES,
  );
  sk.set([...secretKey]);

  const result = kpr(publicKey.byteOffset, sk.byteOffset) as number;

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
  generateMnemonic,
  keyPairFromSeed,
  keyPairFromMnemonic,
  keyPairFromSecretKey,
};
