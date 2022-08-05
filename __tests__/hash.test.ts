import dcrypto from "../src";

describe("Sha512 and Merkle root test suite.", () => {
  test("Public key SHA512 hash works.", async () => {
    const mnemonic = await dcrypto.generateMnemonic();
    const keypair = await dcrypto.keypairFromMnemonic(mnemonic);
    const hash = await dcrypto.sha512(keypair.publicKey);
    expect(hash.length).toBe(64);
  });

  test("Merkle root works.", async () => {
    const tree: Uint8Array[] = [];
    for (let i = 0; i < 201; i++) {
      const rand = await dcrypto.randomBytes(128);
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
