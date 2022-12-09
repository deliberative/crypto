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

  test("Mnemonic generation with different entropy works.", async () => {
    const mnemonic1 = await dcrypto.generateMnemonic(128);
    expect(mnemonic1.split(" ").length).toEqual(12);

    const mnemonic2 = await dcrypto.generateMnemonic(160);
    expect(mnemonic2.split(" ").length).toEqual(15);

    const mnemonic3 = await dcrypto.generateMnemonic(192);
    expect(mnemonic3.split(" ").length).toEqual(18);

    const mnemonic4 = await dcrypto.generateMnemonic(224);
    expect(mnemonic4.split(" ").length).toEqual(21);

    const mnemonic5 = await dcrypto.generateMnemonic(256);
    expect(mnemonic5.split(" ").length).toEqual(24);

    const mnemonic6 = await dcrypto.generateMnemonic(288);
    expect(mnemonic6.split(" ").length).toEqual(27);

    const mnemonic7 = await dcrypto.generateMnemonic(320);
    expect(mnemonic7.split(" ").length).toEqual(30);

    const mnemonic8 = await dcrypto.generateMnemonic(352);
    expect(mnemonic8.split(" ").length).toEqual(33);

    const mnemonic9 = await dcrypto.generateMnemonic(384);
    expect(mnemonic9.split(" ").length).toEqual(36);

    const mnemonic10 = await dcrypto.generateMnemonic(416);
    expect(mnemonic10.split(" ").length).toEqual(39);

    const mnemonic11 = await dcrypto.generateMnemonic(448);
    expect(mnemonic11.split(" ").length).toEqual(42);

    const mnemonic12 = await dcrypto.generateMnemonic(480);
    expect(mnemonic12.split(" ").length).toEqual(45);

    const mnemonic13 = await dcrypto.generateMnemonic(512);
    expect(mnemonic13.split(" ").length).toEqual(48);
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
