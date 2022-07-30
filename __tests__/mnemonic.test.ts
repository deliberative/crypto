import * as bip39 from "bip39";

import dcrypto from "../src";

describe("Mnemonic generation and secret key reconstruction test suite.", () => {
  const mnemonic = dcrypto.generateMnemonic();
  test("Mnemonic generation works.", () => {
    expect(bip39.validateMnemonic(mnemonic)).toBe(true);
  });

  test("Ed25519 keypair from mnemonic works.", async () => {
    const keypair = await dcrypto.keypairFromMnemonic(mnemonic);
    expect(typeof keypair === "object").toBe(true);
  });
});
