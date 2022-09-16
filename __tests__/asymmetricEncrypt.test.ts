import dutils from "@deliberative/utils";

import dcrypto from "../src";

import { crypto_hash_sha512_BYTES } from "../src/utils/interfaces";

describe("Encryption and decryption with Ed25519 derived keys test suite.", () => {
  test("Encryption and decryption work.", async () => {
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

    const encryptionMemory = dcrypto.loadAsymmetricMemory.encrypt(
      message.length,
      crypto_hash_sha512_BYTES,
    );
    const encryptionModule = await dcrypto.loadModule({
      wasmMemory: encryptionMemory,
    });
    const encryptedWithModule = await dcrypto.encryptForwardSecrecy(
      message,
      keypair.publicKey,
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
    const decryptedWithModule = await dcrypto.decryptForwardSecrecy(
      encrypted,
      keypair.secretKey,
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

    const anotherKeypair = await dcrypto.keyPair();

    await expect(
      dcrypto.decryptForwardSecrecy(
        encrypted,
        anotherKeypair.secretKey,
        previousBlockHash,
      ),
    ).rejects.toThrow("Unsuccessful decryption attempt");
  });
});
