# @deliberative/crypto

[![codecov][codecov-image]][codecov-url]
[![Known Vulnerabilities](https://snyk.io/test/github/deliberative/crypto/badge.svg?targetFile=package.json)](https://snyk.io/test/github/deliberative/crypto?targetFile=package.json)
<br>
![NPM Version](https://img.shields.io/npm/v/@deliberative/crypto)
![NPM License](https://img.shields.io/npm/l/@deliberative/crypto)
[![code-style-prettier][code-style-prettier-image]][code-style-prettier-url]
<br>
![NPM Downloads](https://img.shields.io/npm/dw/@deliberative/crypto)
[![](https://data.jsdelivr.com/v1/package/npm/@deliberative/crypto/badge)](https://www.jsdelivr.com/package/npm/@deliberative/crypto)

[codecov-image]: https://codecov.io/gh/deliberative/crypto/branch/master/graph/badge.svg
[codecov-url]: https://codecov.io/gh/deliberative/crypto
[code-style-prettier-image]: https://img.shields.io/badge/code_style-prettier-ff69b4.svg?style=flat-square
[code-style-prettier-url]: https://github.com/prettier/prettier

This repository is part of the reference implementation of the Deliberative Ledger Protocol, the infrastructure for futuristic deliberative democracies.

It does not have any native dependencies and can be used in both Nodejs and the browser.

The API is not completely stable and the code has not undergone external security audits. Use at your own risk.

## Introduction

This library relies heavily on the [libsodium](https://github.com/jedisct1/libsodium) library for the Curve25519 cryptographic operations, which is a battle-tested project, compiled to WebAssembly for speed. In comparison to [tweetnacl](https://github.com/dchest/tweetnacl-js) this library is much faster. Benchmarks will be posted when there is time.

We have also introduced function that can split and restore a secret through the Shamir threshold sharing scheme because we could not find many well-tested open-source implementations of it and we use it heavily in the Deliberative Ledger protocol.

Another feature of the library is a mnemonic generation, validation and Ed25519 key pair from mnemonic that was inspired by [bip39](https://github.com/bitcoinjs/bip39) but instead of Blake2b we use Argon2 and instead of SHA256 we use SHA512, both of which can be found in libsodium.

A last feature is the ability to calculare Merkle roots, proofs and validate proofs from trees of arbitrary types, as
long as you provide a serializer.

## Files

The [libsodium](https://github.com/deliberative/libsodium) directory contains a fork of libsodium whose only differences with the master branch of libsodium are name changes to the implementation structs.

The [asymmetric](src/asymmetric) directory contains asymmetric key cryptography functions. The encryption/decryption
schema is AEAD with forward secrecy, meaning that a throwaway x25519 keypair is generated inside WebAssembly to make the
key exchange with the x25519 equivalent of the client's Ed25519 public key.

The [symmetric](src/symmetric) directory contains AEAD encryption/decryption with a symmetric key.

The [mnemonic](src/mnemonic) directory contains all the relevant to mnemonic generation functions.

The [hash](src/hash) directory contains a sha512 hashing function, a Merkle root getter function, a Merkle
proof artifacts getter and a verification function.

The [shamir](src/shamir) directory contains a WASM implementation of a cryptographic technique called [Shamir's secret
sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing), which allows one to split a secret into random shares that can only recreate it if a threshold of them is combined.
Under the hood it uses the libsodium randombytes js method to generate random coefficients for the polynomial.

The [utils](src/utils) directory contains helper methods such as cryptographic random slicing of arrays etc.

## Getting Started

To get started you have to install the package with

```
npm install @deliberative/crypto
```

You can include as ES module

```typescript
import dcrypto from "@deliberative/crypto";
```

as CommonJS module

```javascript
const dcrypto = require("@deliberative/crypto");
```

or as UMD in the browser with

```html
<script src="https://cdn.jsdelivr.net/npm/@deliberative/crypto@latest/lib/index.min.js"></script>
```

## Examples

You can visit the [examples](examples/js) folder, where you will find examples in
[CommonJS](examples/js/test.cjs), [ES module](examples/js/test.mjs) and
[html in the browser](examples/js/test.html).
For thorough tests of every exposed function you can look the [**tests**](__tests__) folder.

For Curve25519 public key cryptography we have the following methods

```typescript
import dcrypto from "@deliberative/crypto";

// Words from dictionary create random seed for Ed25519 private key.
// Default entropy is 128bits, which results in 12 words.
const mnemonic = await dcrypto.generateMnemonic();
console.log(`Mnemonic with 128 bits of entropy => 12 words: ${mnemonic}`);
// Max entropy is 256bit, where generateMnemonic(256) results in 24 words.

// Keypair is an object representing an Ed25519 keypair with { publicKey: Uint8Array(32), secretKey: Uint8Array(64) }
const keypair = await dcrypto.keyPairFromMnemonic(mnemonic);
console.log(
  `Keypair from mnemonic: {\n\
  secretKey: ${Buffer.from(keypair.secretKey).toString("hex")}\n\
  publicKey: ${Buffer.from(keypair.publicKey).toString("hex")}\n}\
`,
);

// Generates a Uint8Array(128) full of random bytes
const message = await dcrypto.randomBytes(128);

// EdDSA
const signature = await dcrypto.sign(message, keypair.secretKey);

const verify = await dcrypto.verify(message, signature, keypair.publicKey);
console.log(verify); // true

const hash = await dcrypto.sha512(message);

const keypair2 = await dcrypto.keyPair();

// Forward secrecy box.
// Encryptor generates a random keypair. The public key is contained in the
// "encrypted" box and the secret key is used for the key exchange with
// "keypair2.publicKey" and then it is removed from memory.
const encrypted = await dcrypto.encryptForwardSecrecy(
  message,
  keypair2.publicKey,
  hash,
);

const decrypted = await dcrypto.decryptForwardSecrecy(
  encrypted,
  keypair2.secretKey,
  hash,
);

// To test equality for two Uint8Arrays in js you need to check if each of their elements are equal
// The === operator does not work
for (let i = 0; i < message.length; i++) {
  if (message[i] !== decrypted[i]) console.error("Arrays unequal");
}

const symmetricKey = await dcrypto.randomBytes(
  dcrypto.interfaces.crypto_kx_SESSIONKEYBYTES,
);
const encrypted1 = await dcrypto.encrypt(message, symmetricKey, hash);
const decrypted1 = await dcrypto.decrypt(encrypted1, key, hash);
```

For Shamir secret sharing you can test the following

```typescript
import dcrypto from "@deliberative/crypto";

const keypair = await dcrypto.keyPair();

// 100 splitted shares, you need 60 to recreate keypair.secretKey
// Note that you can have max 255 shares and threshold <= shares
const shares = await dcrypto.splitSecret(keypair.secretKey, 100, 60);

// Should be equal to keypair.secretKey
const sk1 = await dcrypto.restoreSecret(shares);

console.log("sk1 and kaypair.secretKey are equal");

// Remove 40 shares to see if it will still work
const lessShares = shares.slice(0, shares.length - 40);

// Should be equal to sk1 and keypair.secretKey
const sk2 = await dcrypto.restoreSecret(lessShares);

console.log("sk2 and kaypair.secretKey are equal");

const evenLessShares = lessShares.slice(0, lessShares.length - 1);

// Should not be equal to sk1 and sk2.
const sk3 = await dcrypto.restoreSecret(evenLessShares);

console.log("sk3 and kaypair.secretKey are NOT equal");
```

In order to find the Merkle root, proof and to verify the proof you can do the following:

```typescript
import dcrypto from "@deliberative/crypto";

const randomArrays: Uint8Array[] = [];
for (let i = 0; i < 50; i++) {
  randomArrays.push(await dcrypto.randomBytes(32));
}

// dcrypto.constants.crypto_hash_sha512_BYTES
// Function also accepts any type of data but it then requires a serializer function.
const randomArraysMerkleRoot = await dcrypto.getMerkleRoot(randomArrays);

// Multiple of dcrypto.constants.crypto_hash_sha512_BYTES
const randomArrayMerkleProof = await dcrypto.getMerkleProof(
  randomArrays,
  randomArrays[43],
);

const elementHash = await dcrypto.sha512(randomArrays[43]);

const verify = await dcrypto.verifyMerkleProof(
  elementHash,
  randomArraysMerkleRoot,
  randomArrayMerkleProof,
);

console.log(verify); // should be true
```

For more examples you can see the [tests](__tests__) directory.

## Development

If you want to bundle the library yourselves, you need to have [Emscripten](https://github.com/emscripten-core/emscripten)
installed on your machine in order to compile the C code into WebAssembly.
We have the `-s SINGLE_FILE=1` option for the `emcc` compiler, which converts the `wasm` file to a `base64` string
that will be compiled by the glue js code into a WebAssembly module. This was done for the purpose of interoperability
and modularity.

Once you have all the dependencies installed, you can run

```
npm run build
```

and [Rollup](https://github.com/rollup/rollup) will generate the UMD, ESM and CJS bundles.

For development compilation you can run

```
npm run build:debug
```

and everything will work in debug mode.

## Releases

Releases are available on [Github](https://github.com/deliberative/crypto/releases)
and [npmjs.com](https://www.npmjs.com/package/@deliberative/crypto)

## License

The source code is licensed under the terms of the Apache License version 2.0 (see [LICENSE](LICENSE)).

## Copyright

Copyright (C) 2022 Deliberative Technologies P.C.
