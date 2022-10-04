import dcrypto from "../src";

import {
  crypto_sign_ed25519_PUBLICKEYBYTES,
  crypto_sign_ed25519_SECRETKEYBYTES,
} from "../src/utils/interfaces";

const arraysAreEqual = (arr1: Uint8Array, arr2: Uint8Array): boolean => {
  const len = arr1.length;
  if (len !== arr2.length) return false;

  for (let i = 0; i < len; i++) {
    if (arr1[i] !== arr2[i]) return false;
  }

  return true;
};

describe("Signing and verifying with Ed25519 keys test suite.", () => {
  test("Mnemonic generation works.", async () => {
    const mnemonic = await dcrypto.generateMnemonic();
    const validate = await dcrypto.validateMnemonic(mnemonic);
    expect(validate).toBe(true);
  });

  test("Generating a new keypair from mnemonic seed works.", async () => {
    const mnemonic = await dcrypto.generateMnemonic();
    const keypair = await dcrypto.keyPairFromMnemonic(mnemonic);

    const anotherKeypair = await dcrypto.keyPairFromMnemonic(mnemonic);

    const keyPairWithPwd = await dcrypto.keyPairFromMnemonic(
      mnemonic,
      "Some password",
    );

    const anotherKeyPairWithPwd = await dcrypto.keyPairFromMnemonic(
      mnemonic,
      "Some password",
    );

    expect(typeof keypair === "object").toBe(true);
    expect(keypair.secretKey.length).toBe(crypto_sign_ed25519_SECRETKEYBYTES);
    expect(keypair.publicKey.length).toBe(crypto_sign_ed25519_PUBLICKEYBYTES);

    expect(arraysAreEqual(keypair.secretKey, anotherKeypair.secretKey)).toBe(
      true,
    );
    expect(
      arraysAreEqual(keyPairWithPwd.secretKey, anotherKeyPairWithPwd.secretKey),
    ).toBe(true);
  });

  test("When an invalid mnemonic gets validated it should be false.", async () => {
    const mnemonicNotMultipleOfThree = `\
abandon \
ability \
about \
above \
absent \
absorb \
abstract \
absurd \
abuse \
access \
accident`;

    const mnemonicHasWordNotInWordlist =
      mnemonicNotMultipleOfThree.concat(" aballon");

    const mnemonicTooShortButMultipleOfThree = mnemonicNotMultipleOfThree
      .replace("abandon ", "")
      .replace("ability ", "");

    const mnemonicTooLongButMultipleOfThree = mnemonicNotMultipleOfThree.concat(
      " advice",
      " aerobic",
      " affair",
      " afford",
      " afraid",
      " again",
      " age",
      " agent",
      " agree",
      " ahead",
      " aim",
      " air",
      " airport",
      " aisle",
      " alarm",
      " album",
      " alcohol",
      " yellow",
      " you",
      " young",
      " youth",
      " zebra",
      " zero",
      " zone",
      " zoo",
      " wood",
      " wool",
      " word",
    );

    const mnemon = await dcrypto.generateMnemonic(256);
    const mnemonArray = mnemon.split(" ");
    const lastWord = mnemonArray[mnemonArray.length - 1];
    const wrongChecksum = mnemon.replace(` ${lastWord}`, " zone");

    const valid1 = await dcrypto.validateMnemonic(mnemonicNotMultipleOfThree);
    const valid2 = await dcrypto.validateMnemonic(mnemonicHasWordNotInWordlist);
    const valid3 = await dcrypto.validateMnemonic(
      mnemonicTooShortButMultipleOfThree,
    );
    const valid4 = await dcrypto.validateMnemonic(
      mnemonicTooLongButMultipleOfThree,
    );
    const valid5 = await dcrypto.validateMnemonic(wrongChecksum);

    expect(valid1).toBe(false);
    expect(valid2).toBe(false);
    expect(valid3).toBe(false);
    expect(valid4).toBe(false);
    expect(valid5).toBe(false);
  });
});
