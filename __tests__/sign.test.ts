import * as nacl from "tweetnacl";

import dcrypto from "../src";

import utils from "../src/utils";

describe("Signing and verifying with Ed25519 keys test suite.", () => {
  const mnemonic = dcrypto.generateMnemonic();

  const randomMessage = nacl.randomBytes(256);

  const stringMessage = "Some random message to sign";

  enum someEnum {
    Hell,
    Yes,
  }

  const objectMessage = {
    data1: "yeah",
    data2: 3,
    data3: someEnum,
    data4: {
      otherData1: "one",
      otherData2: 2,
    },
    data5: [
      {
        otherOtherData1: 3,
        otherOtherData2: "Nice",
        otherOtherData3: someEnum,
      },
    ],
  };

  test("Signing a utf8 message works.", async () => {
    const signature = await dcrypto.sign(stringMessage, mnemonic);
    expect(signature !== null).toBe(true);
    expect(signature.length).toBe(64);
  });

  test("Signing an object message works.", async () => {
    const signature = await dcrypto.sign(objectMessage, mnemonic);
    expect(signature !== null).toBe(true);
    expect(signature.length).toBe(64);
  });

  test("Signing a Uint8Array message works.", async () => {
    const signature = await dcrypto.sign(randomMessage, mnemonic);
    expect(signature !== null).toBe(true);
    expect(signature.length).toBe(64);
  });

  test("Signing the base64 version of a random message works", async () => {
    const b64 = utils.encodeToBase64(randomMessage);
    const signature = await dcrypto.sign(b64, mnemonic);
    expect(signature !== null).toBe(true);
    expect(signature.length).toBe(64);
  });

  test("Verifying the signature of a utf8 message works.", async () => {
    const keypair = await dcrypto.keypairFromMnemonic(mnemonic);
    const signature = await dcrypto.sign(stringMessage, mnemonic);
    const verification = await dcrypto.verify(
      stringMessage,
      signature,
      keypair.publicKey,
    );
    expect(verification).toBe(true);
  });

  test("Verifying the signature of an object message works.", async () => {
    const keypair = await dcrypto.keypairFromMnemonic(mnemonic);
    const signature = await dcrypto.sign(objectMessage, mnemonic);
    const verification = await dcrypto.verify(
      objectMessage,
      signature,
      keypair.publicKey,
    );
    expect(verification).toBe(true);
  });

  test("Verifying the signature of a Uint8Array message works.", async () => {
    const keypair = await dcrypto.keypairFromMnemonic(mnemonic);
    const signature = await dcrypto.sign(randomMessage, mnemonic);
    const verification = await dcrypto.verify(
      randomMessage,
      signature,
      keypair.publicKey,
    );
    expect(verification).toBe(true);
  });

  test("Verifying the signature of a base64 version of a random message works.", async () => {
    const b64 = utils.encodeToBase64(randomMessage);
    const keypair = await dcrypto.keypairFromMnemonic(mnemonic);
    const signature = await dcrypto.sign(b64, mnemonic);
    const verification = await dcrypto.verify(
      b64,
      signature,
      keypair.publicKey,
    );
    expect(verification).toBe(true);
  });

  test("Signing the stringified version of an object and verifying with the object message works.", async () => {
    const keypair = await dcrypto.keypairFromMnemonic(mnemonic);
    const stringifiedObjectMessage = JSON.stringify(objectMessage);
    const signature = await dcrypto.sign(stringifiedObjectMessage, mnemonic);
    const verification = await dcrypto.verify(
      objectMessage,
      signature,
      keypair.publicKey,
    );
    expect(verification).toBe(true);
  });

  test("Verifying signature with wrong key should return false.", async () => {
    const keypair = await dcrypto.keypairFromMnemonic(mnemonic);
    const signature = await dcrypto.sign(objectMessage, keypair.secretKey);
    const wrongKeypair = nacl.sign.keyPair();
    const verification = await dcrypto.verify(
      objectMessage,
      signature,
      wrongKeypair.publicKey,
    );
    expect(verification).toBe(false);
  });
});
