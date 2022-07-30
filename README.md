# @deliberative/crypto

[![codecov][codecov-image]][codecov-url]
<br>
[![npm][npm-image]][npm-url]
[![npm-downloads][npm-downloads-image]][npm-url]
<br>
[![semantic-release][semantic-release-image]][semantic-release-url]
[![code-style-prettier][code-style-prettier-image]][code-style-prettier-url]

[codecov-image]: https://codecov.io/gh/deliberative/crypto/branch/master/graph/badge.svg
[codecov-url]: https://codecov.io/gh/deliberative/crypto
[npm-image]: https://img.shields.io/npm/v/deliberative.svg?style=flat
[npm-downloads-image]: https://img.shields.io/npm/dm/deliberative.svg?style=flat
[npm-url]: https://www.npmjs.com/package/@deliberative/crypto
[semantic-release-image]: https://img.shields.io/badge/%20%20%F0%9F%93%A6%F0%9F%9A%80-semantic--release-e10079.svg
[semantic-release-url]: https://github.com/semantic-release/semantic-release
[code-style-prettier-image]: https://img.shields.io/badge/code_style-prettier-ff69b4.svg?style=flat-square
[code-style-prettier-url]: https://github.com/prettier/prettier

This repository is part of the reference Typescript implementation of the Deliberative Ledger Protocol,
which hopes to become the infrastructure for futuristic deliberative democracies.

This package is stable but it has not undergone external security audits. Use at your own risk.

## Introduction

This package does heavy usage of the [libsodium](https://github.com/jedisct1/libsodium) library in WebAssembly format.
Instead of implementing our own crypto we decided to use a battle-tested implementation of Ed25519 schemes.
We also introduced a Shamir secret sharing utility because we could not find many well-tested open-source implementations
and we utilize it heavily on our Deliberative Ledger protocol.
Finally we introduced some utility functions that make random shuffles, pick random subsets of Uint8Arrays etc.

The [libsodium](https://github.com/deliberative/libsodium) directory contains a fork of libsodium that can compile to wasm
with Emscripten with only the methods that we need.

The [asymmetric](src/asymmetric) directory contains asymmetric key cryptography functions and mnemonic generation.

The [hash](src/hash) directory contains a sha512 hashing function and a Merkle root getter function.

The [shamir](src/shamir) directory contains a Typescript implementation of a cryptographic technique called [Shamir's secret
sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing).
Under the hood it uses the libsodium randombytes js method to generate random coefficients.

The [utils](src/utils) directory contains helper methods such as cryptographic random slicing of arrays etc.

## Getting Started

To get started you have to install the package with
`npm install @deliberative/crypto`

## Examples

For public key cryptography we have the following methods

```typescript
import * as nacl from "tweetnacl";
import dcrypto from "@deliberative/crypto";

// Words from dictionary create random seed for Ed25519 private key.
const mnemonic = dcrypto.generateMnemonic();

// Keypair is an object representing an Ed25519 keypair with { publicKey: Uint8Array(32), secretKey: Uint8Array(64) }
const keypair = await dcrypto.keypairFromMnemonic(mnemonic);

// Message can be string, Uint8Array or object.
// Fastest is Uint8Array
const message = "Some message";

// Can also provide mnemonic instead of private key
const signature = await dcrypto.sign(message, keypair.secretKey);

const verify = await dcrypto.verify(message, signature, keypair.publicKey);
console.log(verify); // true

const hash = dcrypto.sha512(message);

const keypair2 = nacl.sign.keyPair();

const messageUint8 = message.toUint8Array();

const encrypted = await dcrypto.encrypt(message, keypair2.publicKey, hash);

const decrypted = await dcrypto.decrypt(encrypted, keypair2.secretKey, hash);

// To test equality for two Uint8Arrays in js you need to check if each of their elements are equal
// The === operator does not work
const areEqual = dcrypto.arraysAreEqual(messageUint8, decrypted);
console.log(areEqual); // true
```

For Shamir's secret sharing you can test the following

```typescript
import dcrypto from "@deliberative/crypto";

const mnemonic = dcrypto.generateMnemonic();
const keypair = await dcrypto.keypairFromMnemonic(mnemonic);

// 100 splitted shares, you need 60 to recreate keypair.secretKey
const shares = dcrypto.splitSecret(keypair.secretKey, 100, 60);

// Should be equal to keypair.secretKey
const sk1 = dcrypto.restoreSecret(shares);

// To test equality for two Uint8Arrays in js you need to check if each of their elements are equal
// The === operator does not work
// We have deliberative.utils.arraysAreEqual as a method for that.
const areEqual1 = dcrypto.arraysAreEqual(keypair.secretKey, sk1);
console.log(areEqual1); // true

// Remove 40 shares to see if it will still work
const lessShares = shares.slice(0, shares.length - 40);

// Should be equal to sk1 and keypair.secretKey
const sk2 = dcrypto.restoreSecret(lessShares);

const areEqual2 = dcrypto.arraysAreEqual(keypair.secretKey, sk2);
console.log(areEqual2); // true

const evenLessShares = lessShares.slice(0, lessShares.length - 1);

// Should not be equal to sk1 and sk2.
const sk3 = dcrypto.restoreSecret(evenLessShares);

const areEqual3 = dcrypto.arraysAreEqual(keypair.secretKey, sk3);
console.log(areEqual3); // false
```

For cryptographic array utilities you can use the following features

```typescript
import * as nacl from "tweetnacl";
import dcrypto from "@deliberative/crypto";

const someRandomArray = nacl.randomBytes(12); // 12 byte array
console.log(someRandomArray);

// Cryptographic shuffling
const someRandomArrayShuffled = dcrypto.arrayShuffle(someRandomArray);
console.log(someRandomArrayShuffled);

// Choose 5 elements from someRandomArray uniformly.
const someRandomSubArray = dcrypto.arrayRandomSubset(someRandomArray, 5); // 5 elements
console.log(someRandomSubArray);

// Choose 5 other elements and chances are that the arrays are different
const someOtherRandomSubArray = dcrypto.arrayRandomSubset(someRandomArray, 5);
console.log(someOtherRandomSubArray);

const someRandomNumberBetween0and100 = dcrypto.randomNumberInRange(0, 100);
const someOtherRandomNumberBetween0and100 = dcrypto.randomNumberInRange(0, 100);
console.log(someRandomNumberBetween0and100);
console.log(someOtherRandomNumberBetween0and100);
```

For more examples you can see the [tests](__tests__) directory.

## Releases

Releases are available on [Github](https://github.com/deliberative/crypto/releases)
and [npmjs.com](https://www.npmjs.com/package/@deliberative/crypto)

Each Github release features a tarball containing API documentation and a
minified version of the module suitable for direct use in a browser environment
(`<script>` tag)

## License

The source code is licensed under the terms of the Apache License version 2.0 (see [LICENSE](LICENSE)).

## Copyright

Copyright (C) 2022 Deliberative Technologies P.C.
