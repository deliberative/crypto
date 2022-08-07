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

This repository is part of the reference implementation of the Deliberative Ledger Protocol, which hopes to become the infrastructure for futuristic deliberative democracies.

It does not have any native dependencies and can be used in both Nodejs and the browser.

This package is beta-stable but it has not undergone external security audits. Use at your own risk.

## Introduction

This package relies heavily on the [libsodium](https://github.com/jedisct1/libsodium) library for the Curve25519 cryptographic operations.
Instead of implementing our own crypto we decided to use a battle-tested implementation and compile it to WebAssembly for speed.

We have also introduced function that can split and restore a secret through the Shamir threshold sharing method because we could not find many well-tested open-source implementations of it and we use it heavily in the Deliberative Ledger protocol.

Another feature of the library is a mnemonic generation, validation and Ed25519 key pair from mnemonic that was inspired by [bip39](https://github.com/bitcoinjs/bip39) but instead of Blake2b we use Argon2 and instead of SHA256 we use SHA512, both of which can be found in libsodium.

Finally we introduced some utility functions that do random shuffles, pick random subsets of Uint8Arrays etc.

The [libsodium](https://github.com/deliberative/libsodium) directory contains a fork of libsodium whose only differences with the master branch of libsodium are name changes to the implementation structs.

The [asymmetric](src/asymmetric) directory contains asymmetric key cryptography functions.

The [mnemonic](src/mnemonic) directory contains all the relevant to mnemonic generation functions.

The [hash](src/hash) directory contains a sha512 hashing function and a Merkle root getter function.

The [shamir](src/shamir) directory contains a WASM implementation of a cryptographic technique called [Shamir's secret
sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing), which allows one to split a secret into random shares that can only recreate it if a threshold of them is combined.
Under the hood it uses the libsodium randombytes js method to generate random coefficients for the
polynomial.

The [utils](src/utils) directory contains helper methods such as cryptographic random slicing of arrays etc.

## Getting Started

To get started you have to install the package with
`npm install @deliberative/crypto`

## Examples

For public key cryptography we have the following methods

```typescript
import dcrypto from "@deliberative/crypto";

// Words from dictionary create random seed for Ed25519 private key.
const mnemonic = await dcrypto.generateMnemonic();

// Keypair is an object representing an Ed25519 keypair with { publicKey: Uint8Array(32), secretKey: Uint8Array(64) }
const keypair = await dcrypto.keyPairFromMnemonic(mnemonic);

// Generates a Uint8Array(128) full of random bytes
const message = await dcrypto.randomBytes(128);

// Can also provide mnemonic instead of private key
const signature = await dcrypto.sign(message, keypair.secretKey);

const verify = await dcrypto.verify(message, signature, keypair.publicKey);
console.log(verify); // true

const hash = await dcrypto.sha512(message);

const keypair2 = await dcrypto.keyPair();

const encrypted = await dcrypto.encrypt(message, keypair2.publicKey, hash);

const decrypted = await dcrypto.decrypt(encrypted, keypair2.secretKey, hash);

// To test equality for two Uint8Arrays in js you need to check if each of their elements are equal
// The === operator does not work
for (let i = 0; i < message.length; i++) {
  if (message[i] !== decrypted[i]) console.error("Arrays unequal");
}
```

For Shamir's secret sharing you can test the following

```typescript
import dcrypto from "@deliberative/crypto";

const keypair = await dcrypto.keyPair();

// 100 splitted shares, you need 60 to recreate keypair.secretKey
const shares = await dcrypto.splitSecret(keypair.secretKey, 100, 60);

// Should be equal to keypair.secretKey
const sk1 = await dcrypto.restoreSecret(shares);

console.log("sk1 and kaypair.secretKey are equal");

// Remove 40 shares to see if it will still work
const lessShares = shares.slice(0, shares.length - 40);

// Should be equal to sk1 and keypair.secretKey
const sk2 = dcrypto.restoreSecret(lessShares);

console.log("sk2 and kaypair.secretKey are equal");

const evenLessShares = lessShares.slice(0, lessShares.length - 1);

// Should not be equal to sk1 and sk2.
const sk3 = dcrypto.restoreSecret(evenLessShares);

console.log("sk3 and kaypair.secretKey are NOT equal");
```

For cryptographic array utilities you can use the following features

```typescript
import dcrypto from "@deliberative/crypto";

const someRandomArray = await dcrypto.randomBytes(12); // 12 byte array
console.log(someRandomArray);

// Cryptographic shuffling
const someRandomArrayShuffled = await dcrypto.arrayShuffle(someRandomArray);
console.log(someRandomArrayShuffled);

// Choose 5 elements from someRandomArray uniformly.
const someRandomSubArray = await dcrypto.arrayRandomSubset(someRandomArray, 5); // 5 elements
console.log(someRandomSubArray);

// Choose 5 other elements and chances are that the arrays are different
const someOtherRandomSubArray = await dcrypto.arrayRandomSubset(
  someRandomArray,
  5,
);
console.log(someOtherRandomSubArray);

const someRandomNumberBetween0and100 = await dcrypto.randomNumberInRange(
  0,
  100,
);
const someOtherRandomNumberBetween0and100 = await dcrypto.randomNumberInRange(
  0,
  100,
);
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
