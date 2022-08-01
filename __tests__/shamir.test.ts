import dcrypto from "../src";

import utils from "../src/utils";

import { crypto_sign_ed25519_SECRETKEYBYTES } from "../src/interfaces";

describe("Starting the Shamir test suite.", () => {
  test("Splitting a secret key to Shamir shares works.", async () => {
    const mnemonic = await dcrypto.generateMnemonic();
    const keypair = await dcrypto.keypairFromMnemonic(mnemonic);
    const shares = await dcrypto.splitSecret(keypair.secretKey, 100, 60);
    expect(shares.length).toBe(100);
    expect(shares[99].length).toBe(crypto_sign_ed25519_SECRETKEYBYTES + 1);
  });

  test("Combining Shamir shares to recreate a secret key works.", async () => {
    const mnemonic = await dcrypto.generateMnemonic();
    const keypair = await dcrypto.keypairFromMnemonic(mnemonic);
    const sharesLen = 5;
    const threshold = 3;
    const shares = await dcrypto.splitSecret(
      keypair.secretKey,
      sharesLen,
      threshold,
    );

    const secretKey = await dcrypto.restoreSecret(shares);

    const randomSubset1 = await dcrypto.arrayRandomShuffle(shares);
    const secretKey1 = await dcrypto.restoreSecret(randomSubset1);

    const randomSubset2 = await dcrypto.arrayRandomSubset(shares, threshold);
    const secretKey2 = await dcrypto.restoreSecret(randomSubset2);

    const randomSubset3 = await dcrypto.arrayRandomSubset(
      shares,
      threshold - 1,
    );
    const secretKey3 = await dcrypto.restoreSecret(randomSubset3);

    expect(secretKey.length === keypair.secretKey.length).toBe(true);
    expect(utils.arraysAreEqual(secretKey, keypair.secretKey)).toBe(true);
    expect(utils.arraysAreEqual(secretKey1, keypair.secretKey)).toBe(true);
    expect(utils.arraysAreEqual(secretKey2, keypair.secretKey)).toBe(true);
    expect(utils.arraysAreEqual(secretKey3, keypair.secretKey)).toBe(false);
  });
});
