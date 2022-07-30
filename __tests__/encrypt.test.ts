import * as nacl from "tweetnacl";

import dcrypto from "../src";

describe("Encryption and decryption with Ed25519 derived keys test suite.", () => {
  test("Encryption and decryption work.", async () => {
    const message = nacl.randomBytes(32);
    // const keypair1 = nacl.sign.keyPair();
    const keypair2 = nacl.sign.keyPair();

    const previousBlockHash = nacl.randomBytes(nacl.hash.hashLength);
    const encrypted = await dcrypto.encrypt(
      message,
      keypair2.publicKey,
      // keypair1.secretKey,
      previousBlockHash,
    );

    const decrypted = await dcrypto.decrypt(
      encrypted,
      // keypair1.publicKey,
      keypair2.secretKey,
      previousBlockHash,
    );

    expect(decrypted[0]).toBe(message[0]);
    expect(decrypted[1]).toBe(message[1]);
    expect(decrypted[31]).toBe(message[31]);
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
