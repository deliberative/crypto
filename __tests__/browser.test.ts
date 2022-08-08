/**
 * @jest-environment jsdom
 */

import dcrypto from "../src";

import {
  crypto_sign_ed25519_SECRETKEYBYTES,
  crypto_hash_sha512_BYTES,
} from "../src/utils/interfaces";

import arraysAreEqual from "../src/utils/arraysAreEqual";

describe("Browser-based tests.", () => {
  test("Generating random bytes with webcrypto works.", async () => {
    const message = await dcrypto.randomBytes(32);
    const keypair = await dcrypto.keyPair();

    const previousBlockHash = await dcrypto.randomBytes(
      crypto_hash_sha512_BYTES,
    );

    const encrypted = await dcrypto.encrypt(
      message,
      keypair.publicKey,
      previousBlockHash,
    );

    const decrypted = await dcrypto.decrypt(
      encrypted,
      keypair.secretKey,
      previousBlockHash,
    );

    expect(decrypted[0]).toBe(message[0]);
    expect(decrypted[1]).toBe(message[1]);
    expect(decrypted[31]).toBe(message[31]);
  });

  test("Loading libsodium wasm module in the browser and crypto operations work.", async () => {
    const randomBytes = await dcrypto.randomBytes(256);
    const hash = await dcrypto.sha512(randomBytes);
    const keypair = await dcrypto.keyPair();
    const signature = await dcrypto.sign(randomBytes, keypair.secretKey);
    const verification = await dcrypto.verify(
      randomBytes,
      signature,
      keypair.publicKey,
    );
    const encrypted = await dcrypto.encrypt(
      randomBytes,
      keypair.publicKey,
      hash,
    );
    const decrypted = await dcrypto.decrypt(encrypted, keypair.secretKey, hash);
    expect(verification).toBe(true);
    expect(arraysAreEqual(randomBytes, decrypted)).toBe(true);
  });

  test("Loading shamir wasm module in the browser and splitting/restoring works.", async () => {
    const shamirMemory = dcrypto.loadShamirMemory.splitSecret(
      crypto_sign_ed25519_SECRETKEYBYTES,
      20,
      11,
    );
    const shamirModule = await dcrypto.loadShamirModule({
      wasmMemory: shamirMemory,
    });
    const keypair = await dcrypto.keyPair();
    const shares = await dcrypto.splitSecret(
      keypair.secretKey,
      10,
      6,
      shamirModule,
    );
    const shuffled = await dcrypto.arrayRandomShuffle(shares);
    const reconstructed = await dcrypto.restoreSecret(shuffled, shamirModule);
    expect(arraysAreEqual(keypair.secretKey, reconstructed)).toBe(true);
  });

  test("Loading utils wasm module in the browser and operations work.", async () => {
    const min = 1;
    const max = 256000;
    const someNumber = await dcrypto.randomNumberInRange(min, max);
    const someOtherNumber = await dcrypto.randomNumberInRange(min, max);
    const someArray = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    const reshuffled = await dcrypto.arrayRandomShuffle(someArray);
    let everyElementInSamePlace = true;
    for (let i = 0; i < reshuffled.length; i++) {
      if (someArray[i] !== reshuffled[i]) {
        everyElementInSamePlace = false;
      }
    }
    expect(everyElementInSamePlace).toBe(false);
    expect(min).toBeLessThanOrEqual(someNumber);
    expect(someNumber).toBeLessThanOrEqual(max);
    expect(someNumber === someOtherNumber).toBe(false);
  });
});
