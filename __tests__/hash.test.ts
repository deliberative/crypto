import * as nacl from "tweetnacl";

import dcrypto from "../src";

describe("Sha512 and Merkle root test suite.", () => {
  const mnemonic = dcrypto.generateMnemonic();

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

  test("Public key SHA512 hash works.", async () => {
    const keypair = await dcrypto.keypairFromMnemonic(mnemonic);
    const hash = await dcrypto.sha512(keypair.publicKey);
    expect(hash.length).toBe(64);
  });

  test("Sha512 on objects works.", async () => {
    const hash = await dcrypto.sha512(objectMessage);
    expect(hash.length).toBe(64);
  });

  test("Sha512 on strings works.", async () => {
    const data = JSON.stringify(stringMessage);
    const hash = await dcrypto.sha512(data);
    expect(hash.length).toBe(64);
  });

  test("Merkle root works.", async () => {
    const tree: Uint8Array[] = [];
    for (let i = 0; i < 201; i++) {
      const rand = nacl.randomBytes(128);
      tree.push(rand);
    }

    const root = await dcrypto.getMerkleRoot(tree);

    const root2 = await dcrypto.getMerkleRoot(tree);

    expect(root.length).toBe(64);
    expect(root[0]).toBe(root2[0]);
    expect(root[1]).toBe(root2[1]);
    expect(root[63]).toBe(root2[63]);
  });
});
