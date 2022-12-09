import dcrypto from "../src";
import nacl from "tweetnacl";

describe("Sha512 and Argon2 test suite.", () => {
  test("Public key SHA512 hash works.", async () => {
    const mnemonic = await dcrypto.generateMnemonic();
    const keypair = await dcrypto.keyPairFromMnemonic(mnemonic);
    const hash = await dcrypto.sha512(keypair.publicKey);
    expect(hash.length).toBe(64);
  });

  test("Output of SHA512 hash should be equal to tweetnacl.", async () => {
    const message = await dcrypto.randomBytes(256);
    const hash1 = await dcrypto.sha512(message);
    const hash2 = nacl.hash(message);
    expect(hash1).toStrictEqual(hash2);
  });

  test("Mnemonic Argon2 hash works.", async () => {
    const mnemonic = await dcrypto.generateMnemonic();
    const hash = await dcrypto.argon2(mnemonic);
    expect(hash.length).toBe(32);
  });
});
