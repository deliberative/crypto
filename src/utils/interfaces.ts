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

export interface SignKeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export type TypedArray =
  | Int8Array
  | Uint8Array
  | Int16Array
  | Uint16Array
  | Int32Array
  | Uint32Array
  | Uint8ClampedArray
  | Float32Array
  | Float64Array;

export const crypto_hash_sha512_BYTES = 64 * Uint8Array.BYTES_PER_ELEMENT;
export const crypto_secretbox_KEYBYTES = 32 * Uint8Array.BYTES_PER_ELEMENT;
export const crypto_secretbox_NONCEBYTES = 24 * Uint8Array.BYTES_PER_ELEMENT;
export const crypto_box_poly1305_AUTHTAGBYTES =
  16 * Uint8Array.BYTES_PER_ELEMENT;
export const crypto_box_x25519_PUBLICKEYBYTES =
  32 * Uint8Array.BYTES_PER_ELEMENT;
export const crypto_box_x25519_SECRETKEYBYTES =
  32 * Uint8Array.BYTES_PER_ELEMENT;
export const crypto_box_x25519_NONCEBYTES = 12 * Uint8Array.BYTES_PER_ELEMENT;
export const crypto_kx_SESSIONKEYBYTES = 32 * Uint8Array.BYTES_PER_ELEMENT;
export const crypto_sign_ed25519_BYTES = 64 * Uint8Array.BYTES_PER_ELEMENT;
export const crypto_sign_ed25519_SEEDBYTES = 32 * Uint8Array.BYTES_PER_ELEMENT;
export const crypto_sign_ed25519_PUBLICKEYBYTES =
  32 * Uint8Array.BYTES_PER_ELEMENT;
export const crypto_sign_ed25519_SECRETKEYBYTES =
  64 * Uint8Array.BYTES_PER_ELEMENT;
export const crypto_pwhash_argon2id_SALTBYTES =
  16 * Uint8Array.BYTES_PER_ELEMENT;

export const getEncryptedLen = (dataLen: number) => {
  return (
    crypto_box_x25519_NONCEBYTES + // xchacha uses 24 byte nonce while ietf 12
    dataLen +
    crypto_box_poly1305_AUTHTAGBYTES // 16 bytes poly1305 auth tag
  );
};

export const getDecryptedLen = (encryptedLen: number) => {
  return (
    encryptedLen -
    crypto_box_x25519_NONCEBYTES - // nonce
    crypto_box_poly1305_AUTHTAGBYTES // authTag
  );
};

export const getForwardSecretBoxEncryptedLen = (dataLen: number) => {
  return (
    crypto_box_x25519_PUBLICKEYBYTES + // ephemeral x25519 public key
    crypto_box_x25519_NONCEBYTES + // xchacha uses 24 byte nonce while ietf 12
    dataLen +
    crypto_box_poly1305_AUTHTAGBYTES // 16 bytes poly1305 auth tag
  );
};

export const getForwardSecretBoxDecryptedLen = (encryptedLen: number) => {
  return (
    encryptedLen -
    crypto_box_x25519_PUBLICKEYBYTES - // x25519 ephemeral
    crypto_box_x25519_NONCEBYTES - // nonce
    crypto_box_poly1305_AUTHTAGBYTES // authTag
  );
};

export default {
  crypto_hash_sha512_BYTES,
  crypto_secretbox_KEYBYTES,
  crypto_secretbox_NONCEBYTES,
  crypto_box_poly1305_AUTHTAGBYTES,
  crypto_box_x25519_PUBLICKEYBYTES,
  crypto_box_x25519_SECRETKEYBYTES,
  crypto_box_x25519_NONCEBYTES,
  crypto_kx_SESSIONKEYBYTES,
  crypto_sign_ed25519_BYTES,
  crypto_sign_ed25519_SEEDBYTES,
  crypto_sign_ed25519_PUBLICKEYBYTES,
  crypto_sign_ed25519_SECRETKEYBYTES,
  crypto_pwhash_argon2id_SALTBYTES,
  getEncryptedLen,
  getDecryptedLen,
  getForwardSecretBoxEncryptedLen,
  getForwardSecretBoxDecryptedLen,
};
