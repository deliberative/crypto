import dcrypto from "../src";

import {
  crypto_hash_sha512_BYTES,
  crypto_kx_SESSIONKEYBYTES,
} from "../src/utils/interfaces";

const arraysAreEqual = (arr1: Uint8Array, arr2: Uint8Array): boolean => {
  const len = arr1.length;
  if (len !== arr2.length) return false;

  for (let i = 0; i < len; i++) {
    if (arr1[i] !== arr2[i]) return false;
  }

  return true;
};

describe("Encryption and decryption with symmetric key test suite.", () => {
  test("Encryption and decryption work.", async () => {
    const message = await dcrypto.randomBytes(32);
    const key = await dcrypto.randomBytes(crypto_kx_SESSIONKEYBYTES);

    const previousBlockHash = await dcrypto.randomBytes(
      crypto_hash_sha512_BYTES,
    );

    const encrypted = await dcrypto.encryptSymmetricKey(
      message,
      key,
      previousBlockHash,
    );
    const decrypted = await dcrypto.decryptSymmetricKey(
      encrypted,
      key,
      previousBlockHash,
    );

    const encryptionMemory = dcrypto.loadWasmMemory.encryptSymmetricKey(
      message.length,
      crypto_hash_sha512_BYTES,
    );
    const encryptionModule = await dcrypto.loadModule({
      wasmMemory: encryptionMemory,
    });
    const encryptedWithModule = await dcrypto.encryptSymmetricKey(
      message,
      key,
      previousBlockHash,
      encryptionModule,
    );

    const decryptionMemory = dcrypto.loadWasmMemory.decryptSymmetricKey(
      encrypted.length,
      crypto_hash_sha512_BYTES,
    );
    const decryptionModule = await dcrypto.loadModule({
      wasmMemory: decryptionMemory,
    });
    const decryptedWithModule = await dcrypto.decryptSymmetricKey(
      encrypted,
      key,
      previousBlockHash,
      decryptionModule,
    );

    expect(decrypted[0]).toBe(message[0]);
    expect(decrypted[1]).toBe(message[1]);
    expect(decrypted[31]).toBe(message[31]);
    expect(arraysAreEqual(encryptedWithModule, encrypted)).toBe(false);
    expect(arraysAreEqual(decryptedWithModule, decrypted)).toBe(true);
  });

  it("Should be impossible to decrypt with wrong key", async () => {
    const message = await dcrypto.randomBytes(32);
    const key = await dcrypto.randomBytes(crypto_kx_SESSIONKEYBYTES);

    const previousBlockHash = await dcrypto.randomBytes(
      crypto_hash_sha512_BYTES,
    );
    const encrypted = await dcrypto.encryptSymmetricKey(
      message,
      key,
      previousBlockHash,
    );

    const anotherKey = await dcrypto.randomBytes(crypto_kx_SESSIONKEYBYTES);

    await expect(
      dcrypto.decryptSymmetricKey(encrypted, anotherKey, previousBlockHash),
    ).rejects.toThrow("Unsuccessful decryption attempt");
  });
});
