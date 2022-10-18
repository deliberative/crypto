import dcrypto from "../src";

describe("Sha512 and Argon2 test suite.", () => {
  test("Public key SHA512 hash works.", async () => {
    const mnemonic = await dcrypto.generateMnemonic();
    const keypair = await dcrypto.keyPairFromMnemonic(mnemonic);
    const hash = await dcrypto.sha512(keypair.publicKey);
    expect(hash.length).toBe(64);
  });

  test("Mnemonic Argon2 hash works.", async () => {
    const mnemonic = await dcrypto.generateMnemonic();
    const hash = await dcrypto.argon2(mnemonic);
    expect(hash.length).toBe(32);
  });
});
