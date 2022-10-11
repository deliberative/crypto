import dcrypto from "../src";

import {
  crypto_sign_ed25519_PUBLICKEYBYTES,
  crypto_sign_ed25519_SECRETKEYBYTES,
  crypto_sign_ed25519_SEEDBYTES,
} from "../src/utils/interfaces";

const arraysAreEqual = (arr1: Uint8Array, arr2: Uint8Array): boolean => {
  const len = arr1.length;
  if (len !== arr2.length) return false;

  for (let i = 0; i < len; i++) {
    if (arr1[i] !== arr2[i]) return false;
  }

  return true;
};

describe("Signing and verifying with Ed25519 keys test suite.", () => {
  test("Generating a new keypair works.", async () => {
    const keypair = await dcrypto.keyPair();

    const wasmMemory = dcrypto.loadWasmMemory.newKeyPair();
    const module = await dcrypto.loadWasmModule({ wasmMemory });
    const someOtherKeypair = await dcrypto.keyPair(module);

    expect(typeof keypair === "object").toBe(true);
    expect(keypair.secretKey.length).toBe(crypto_sign_ed25519_SECRETKEYBYTES);
    expect(keypair.publicKey.length).toBe(crypto_sign_ed25519_PUBLICKEYBYTES);

    expect(arraysAreEqual(keypair.secretKey, someOtherKeypair.secretKey)).toBe(
      false,
    );
  });

  test("Generating a new keypair from a random seed works.", async () => {
    const seed = await dcrypto.randomBytes(crypto_sign_ed25519_SEEDBYTES);
    const keypair = await dcrypto.keyPairFromSeed(seed);

    const wasmMemory = dcrypto.loadWasmMemory.keyPairFromSeed();
    const module = await dcrypto.loadWasmModule({ wasmMemory });
    const sameKeypair = await dcrypto.keyPairFromSeed(seed, module);

    expect(typeof keypair === "object").toBe(true);
    expect(keypair.secretKey.length).toBe(crypto_sign_ed25519_SECRETKEYBYTES);
    expect(keypair.publicKey.length).toBe(crypto_sign_ed25519_PUBLICKEYBYTES);

    expect(arraysAreEqual(sameKeypair.secretKey, keypair.secretKey)).toBe(true);
  });

  test("Generating a new keypair from a secret key works.", async () => {
    const original = await dcrypto.keyPair();
    const keypair = await dcrypto.keyPairFromSecretKey(original.secretKey);

    const wasmMemory = dcrypto.loadWasmMemory.keyPairFromSecretKey();
    const module = await dcrypto.loadWasmModule({ wasmMemory });
    const sameKeypair = await dcrypto.keyPairFromSecretKey(
      original.secretKey,
      module,
    );

    expect(typeof keypair === "object").toBe(true);
    expect(keypair.secretKey.length).toBe(crypto_sign_ed25519_SECRETKEYBYTES);
    expect(keypair.publicKey.length).toBe(crypto_sign_ed25519_PUBLICKEYBYTES);
    expect(arraysAreEqual(original.publicKey, keypair.publicKey)).toBe(true);

    expect(arraysAreEqual(sameKeypair.secretKey, original.secretKey)).toBe(
      true,
    );
  });

  test("Signing a Uint8Array message works.", async () => {
    const keyPair = await dcrypto.keyPair();
    const randomMessage = await dcrypto.randomBytes(256);
    const signature = await dcrypto.sign(randomMessage, keyPair.secretKey);

    const wasmMemory = dcrypto.loadWasmMemory.sign(randomMessage.length);
    const module = await dcrypto.loadWasmModule({ wasmMemory });
    const otherSignature = await dcrypto.sign(
      randomMessage,
      keyPair.secretKey,
      module,
    );

    expect(signature !== null).toBe(true);
    expect(signature.length).toBe(64);

    expect(arraysAreEqual(signature, otherSignature)).toBe(true);
  });

  test("Verifying the signature of a Uint8Array message works.", async () => {
    const mnemonic = await dcrypto.generateMnemonic();
    const keypair = await dcrypto.keyPairFromMnemonic(mnemonic);
    const randomMessage = await dcrypto.randomBytes(256);
    const signature = await dcrypto.sign(randomMessage, keypair.secretKey);
    const verification = await dcrypto.verify(
      randomMessage,
      signature,
      keypair.publicKey,
    );

    const wasmMemory = dcrypto.loadWasmMemory.verify(randomMessage.length);
    const module = await dcrypto.loadWasmModule({ wasmMemory });
    const otherVerification = await dcrypto.verify(
      randomMessage,
      signature,
      keypair.publicKey,
      module,
    );

    expect(verification).toBe(true);
    expect(otherVerification).toBe(true);
  });

  test("Verifying signature with wrong key should return false.", async () => {
    const rightKeyPair = await dcrypto.keyPair();
    const wrongKeyPair = await dcrypto.keyPair();
    const randomMessage = await dcrypto.randomBytes(10240);
    const signature = await dcrypto.sign(randomMessage, rightKeyPair.secretKey);
    const verification = await dcrypto.verify(
      randomMessage,
      signature,
      wrongKeyPair.publicKey,
    );

    expect(verification).toBe(false);
  });
});
