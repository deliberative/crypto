import dutils from "@deliberative/utils";

import dcrypto from "../src";

describe("Sha512 and Merkle root test suite.", () => {
  test("Public key SHA512 hash works.", async () => {
    const mnemonic = await dcrypto.generateMnemonic();
    const keypair = await dcrypto.keyPairFromMnemonic(mnemonic);
    const hash = await dcrypto.sha512(keypair.publicKey);
    expect(hash.length).toBe(64);
  });

  test("Merkle root calculation works.", async () => {
    const tree: Uint8Array[] = [];
    for (let i = 0; i < 201; i++) {
      const rand = await dutils.randomBytes(128);
      tree.push(rand);
    }

    const root = await dcrypto.getMerkleRoot(tree);

    const root2 = await dcrypto.getMerkleRoot(tree);

    expect(root.length).toBe(64);
    expect(root[0]).toBe(root2[0]);
    expect(root[1]).toBe(root2[1]);
    expect(root[63]).toBe(root2[63]);
  });

  test("Merkle proof verification works for odd number of elements.", async () => {
    const tree: Uint8Array[] = [];
    const element = new Uint8Array(128);
    const elements = 201;
    const elementIndex = 99;
    for (let i = 0; i < elements; i++) {
      const rand = await dutils.randomBytes(128);

      if (i === elementIndex) element.set([...rand]);

      tree.push(rand);
    }

    const root = await dcrypto.getMerkleRoot(tree);

    const proofLeaves = await dcrypto.getMerkleProofArtifacts(
      tree,
      elementIndex,
    );

    const elementHash = await dcrypto.sha512(element);

    const verification = await dcrypto.verifyMerkleProof(
      elementHash,
      root,
      proofLeaves,
    );

    expect(verification).toBe(true);
  });

  test("Merkle proof verification works for even number of elements.", async () => {
    const tree: Uint8Array[] = [];
    const element = new Uint8Array(128);
    const elements = 200;
    const elementIndex = 99;
    for (let i = 0; i < elements; i++) {
      const rand = await dutils.randomBytes(128);

      if (i === elementIndex) element.set([...rand]);

      tree.push(rand);
    }

    const root = await dcrypto.getMerkleRoot(tree);

    const proofLeaves = await dcrypto.getMerkleProofArtifacts(
      tree,
      elementIndex,
    );

    const elementHash = await dcrypto.sha512(element);

    const verification = await dcrypto.verifyMerkleProof(
      elementHash,
      root,
      proofLeaves,
    );

    expect(verification).toBe(true);
  });
});
