import dcrypto from "../src";

import {
  crypto_sign_ed25519_PUBLICKEYBYTES,
  crypto_sign_ed25519_SECRETKEYBYTES,
} from "../src/utils/interfaces";

describe("Signing and verifying with Ed25519 keys test suite.", () => {
  test("Mnemonic generation works.", async () => {
    const mnemonic = await dcrypto.generateMnemonic();
    const validate = await dcrypto.validateMnemonic(mnemonic);
    expect(validate).toBe(true);
  });

  test("Generating a new keypair from mnemonic seed works.", async () => {
    const mnemonic = await dcrypto.generateMnemonic();
    const keypair = await dcrypto.keypairFromMnemonic(mnemonic);
    expect(typeof keypair === "object").toBe(true);
    expect(keypair.secretKey.length).toBe(crypto_sign_ed25519_SECRETKEYBYTES);
    expect(keypair.publicKey.length).toBe(crypto_sign_ed25519_PUBLICKEYBYTES);
  });
});
