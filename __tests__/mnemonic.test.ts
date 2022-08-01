import * as bip39 from "bip39";

import dcrypto from "../src";

describe("Mnemonic generation and secret key reconstruction test suite.", () => {
  test("Mnemonic generation works.", async () => {
    const mnemonic = await dcrypto.generateMnemonic();
    expect(bip39.validateMnemonic(mnemonic)).toBe(true);
  });

  test("Ed25519 keypair from mnemonic works.", async () => {
    const mnemonic = await dcrypto.generateMnemonic();
    const keypair = await dcrypto.keypairFromMnemonic(mnemonic);
    expect(typeof keypair === "object").toBe(true);
  });
});
