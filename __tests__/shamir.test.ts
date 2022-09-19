import dutils from "@deliberative/utils";

import dcrypto from "../src";

import { crypto_sign_ed25519_SECRETKEYBYTES } from "../src/utils/interfaces";

describe("Starting the Shamir test suite.", () => {
  test("Splitting a secret key to Shamir shares works.", async () => {
    const mnemonic = await dcrypto.generateMnemonic();
    const keypair = await dcrypto.keyPairFromMnemonic(mnemonic);
    const shares = await dcrypto.splitSecret(keypair.secretKey, 10, 6);
    expect(shares.length).toBe(10);
    expect(shares[9].length).toBe(crypto_sign_ed25519_SECRETKEYBYTES + 1);
  });

  it("Should be impossible to split a secret of length less than 2.", async () => {
    const secret = new Uint8Array(1).fill(4);
    await expect(dcrypto.splitSecret(secret, 10, 6)).rejects.toThrow(
      "Need more data",
    );
  });

  it("Should be impossible to split a secret with threshold less than 2.", async () => {
    const secret = await dutils.randomBytes(256);
    await expect(dcrypto.splitSecret(secret, 10, 1)).rejects.toThrow(
      "Threshold is less than 2",
    );
  });

  it("Should be impossible to split a secret into shares less than threshold.", async () => {
    const secret = await dutils.randomBytes(256);
    await expect(dcrypto.splitSecret(secret, 10, 11)).rejects.toThrow(
      "Shares are less than threshold",
    );
  });

  it("Should be impossible to split a secret into more than 255 shares.", async () => {
    const secret = await dutils.randomBytes(256);
    await expect(dcrypto.splitSecret(secret, 256, 11)).rejects.toThrow(
      "Shares exceed 255",
    );
  });

  test("Combining Shamir shares to recreate a secret key works.", async () => {
    const mnemonic = await dcrypto.generateMnemonic();
    const keypair = await dcrypto.keyPairFromMnemonic(mnemonic);
    const sharesLen = 9;
    const threshold = 5;
    const shares = await dcrypto.splitSecret(
      keypair.secretKey,
      sharesLen,
      threshold,
    );

    const secretKey = await dcrypto.restoreSecret(shares);

    const randomSubset1 = await dutils.arrayRandomShuffle(shares);
    const secretKey1 = await dcrypto.restoreSecret(randomSubset1);

    const randomSubset2 = await dutils.arrayRandomSubset(shares, threshold);
    const secretKey2 = await dcrypto.restoreSecret(randomSubset2);

    const randomSubset3 = await dutils.arrayRandomSubset(shares, threshold - 1);
    const secretKey3 = await dcrypto.restoreSecret(randomSubset3);

    expect(secretKey.length === keypair.secretKey.length).toBe(true);
    expect(await dutils.arraysAreEqual(secretKey, keypair.secretKey)).toBe(
      true,
    );
    expect(await dutils.arraysAreEqual(secretKey1, keypair.secretKey)).toBe(
      true,
    );
    expect(await dutils.arraysAreEqual(secretKey2, keypair.secretKey)).toBe(
      true,
    );
    expect(await dutils.arraysAreEqual(secretKey3, keypair.secretKey)).toBe(
      false,
    );
  });

  it("Should be impossible to restore a shared secret with less than 2 shares.", async () => {
    const shares = [new Uint8Array(13)];
    await expect(dcrypto.restoreSecret(shares)).rejects.toThrow(
      "Not enough shares provided.",
    );
  });

  it("Should be impossible to restore a shared secret with more than 255 shares.", async () => {
    const shares: Uint8Array[] = [];
    for (let i = 0; i < 257; i++) {
      shares.push(new Uint8Array(20));
    }
    await expect(dcrypto.restoreSecret(shares)).rejects.toThrow(
      "Need at most 255 shares.",
    );
  });

  it("Should be impossible to restore a shared secret with shares of variable length.", async () => {
    const shares: Uint8Array[] = [];
    shares.push(new Uint8Array(8));
    shares.push(new Uint8Array(10));
    await expect(dcrypto.restoreSecret(shares)).rejects.toThrow(
      "Shares length varies.",
    );
  });
});
