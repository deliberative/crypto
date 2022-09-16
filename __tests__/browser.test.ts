/**
 * @jest-environment jsdom
 */

import dutils from "@deliberative/utils";

import dcrypto from "../src";

import {
  crypto_sign_ed25519_SECRETKEYBYTES,
  crypto_hash_sha512_BYTES,
} from "../src/utils/interfaces";

describe("Browser-based tests.", () => {
  test("Generating random bytes with webcrypto works.", async () => {
    const message = await dcrypto.randomBytes(32);
    const keypair = await dcrypto.keyPair();

    const previousBlockHash = await dcrypto.randomBytes(
      crypto_hash_sha512_BYTES,
    );

    const encrypted = await dcrypto.encryptForwardSecrecy(
      message,
      keypair.publicKey,
      previousBlockHash,
    );

    const decrypted = await dcrypto.decryptForwardSecrecy(
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
    const key = await dcrypto.randomBytes(
      dcrypto.interfaces.crypto_kx_SESSIONKEYBYTES,
    );
    const keypair = await dcrypto.keyPair();
    const signature = await dcrypto.sign(randomBytes, keypair.secretKey);
    const verification = await dcrypto.verify(
      randomBytes,
      signature,
      keypair.publicKey,
    );
    const encrypted = await dcrypto.encryptForwardSecrecy(
      randomBytes,
      keypair.publicKey,
      hash,
    );
    const decrypted = await dcrypto.decryptForwardSecrecy(
      encrypted,
      keypair.secretKey,
      hash,
    );
    const encrypted1 = await dcrypto.encrypt(randomBytes, key, hash);
    const decrypted1 = await dcrypto.decrypt(encrypted1, key, hash);
    expect(verification).toBe(true);
    expect(await dutils.arraysAreEqual(randomBytes, decrypted)).toBe(true);
    expect(await dutils.arraysAreEqual(randomBytes, decrypted1)).toBe(true);
  });

  test("Loading shamir wasm module in the browser and splitting/restoring works.", async () => {
    const shamirSplitMemory = dcrypto.loadShamirMemory.splitSecret(
      crypto_sign_ed25519_SECRETKEYBYTES,
      20,
      11,
    );
    const splitModule = await dcrypto.loadModule({
      wasmMemory: shamirSplitMemory,
    });
    const keypair = await dcrypto.keyPair();
    const shares = await dcrypto.splitSecret(
      keypair.secretKey,
      10,
      6,
      splitModule,
    );

    const shuffled = await dutils.arrayRandomShuffle(shares);

    const shamirRestoreMemory = dcrypto.loadShamirMemory.restoreSecret(
      crypto_sign_ed25519_SECRETKEYBYTES,
      20,
    );
    const restoreModule = await dcrypto.loadModule({
      wasmMemory: shamirRestoreMemory,
    });
    const reconstructed = await dcrypto.restoreSecret(shuffled, restoreModule);

    expect(await dutils.arraysAreEqual(keypair.secretKey, reconstructed)).toBe(
      true,
    );
  });

  test("Loading utils wasm module in the browser and operations work.", async () => {
    const min = 1;
    const max = 256000;
    const someNumber = await dutils.randomNumberInRange(min, max);
    const someOtherNumber = await dutils.randomNumberInRange(min, max);
    const someArray = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    const reshuffled = await dutils.arrayRandomShuffle(someArray);
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
