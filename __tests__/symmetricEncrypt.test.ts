import dutils from "@deliberative/utils";

import dcrypto from "../src";

import {
  crypto_hash_sha512_BYTES,
  crypto_kx_SESSIONKEYBYTES,
} from "../src/utils/interfaces";

describe("Encryption and decryption with symmetric key test suite.", () => {
  test("Encryption and decryption work.", async () => {
    const message = await dutils.randomBytes(32);
    const key = await dutils.randomBytes(crypto_kx_SESSIONKEYBYTES);

    const previousBlockHash = await dutils.randomBytes(
      crypto_hash_sha512_BYTES,
    );

    const encrypted = await dcrypto.encrypt(message, key, previousBlockHash);
    const decrypted = await dcrypto.decrypt(encrypted, key, previousBlockHash);

    const encryptionMemory = dcrypto.loadAsymmetricMemory.encrypt(
      message.length,
      crypto_hash_sha512_BYTES,
    );
    const encryptionModule = await dcrypto.loadModule({
      wasmMemory: encryptionMemory,
    });
    const encryptedWithModule = await dcrypto.encrypt(
      message,
      key,
      previousBlockHash,
      encryptionModule,
    );

    const decryptionMemory = dcrypto.loadAsymmetricMemory.decrypt(
      encrypted.length,
      crypto_hash_sha512_BYTES,
    );
    const decryptionModule = await dcrypto.loadModule({
      wasmMemory: decryptionMemory,
    });
    const decryptedWithModule = await dcrypto.decrypt(
      encrypted,
      key,
      previousBlockHash,
      decryptionModule,
    );

    expect(decrypted[0]).toBe(message[0]);
    expect(decrypted[1]).toBe(message[1]);
    expect(decrypted[31]).toBe(message[31]);
    expect(await dutils.arraysAreEqual(encryptedWithModule, encrypted)).toBe(
      false,
    );
    expect(await dutils.arraysAreEqual(decryptedWithModule, decrypted)).toBe(
      true,
    );
  });

  it("Should be impossible to decrypt with wrong key", async () => {
    const message = await dutils.randomBytes(32);
    const key = await dutils.randomBytes(crypto_kx_SESSIONKEYBYTES);

    const previousBlockHash = await dutils.randomBytes(
      crypto_hash_sha512_BYTES,
    );
    const encrypted = await dcrypto.encrypt(message, key, previousBlockHash);

    const anotherKey = await dutils.randomBytes(crypto_kx_SESSIONKEYBYTES);

    await expect(
      dcrypto.decrypt(encrypted, anotherKey, previousBlockHash),
    ).rejects.toThrow("Unsuccessful decryption attempt");
  });
});
