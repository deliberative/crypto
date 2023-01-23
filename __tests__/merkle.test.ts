import dcrypto from "../src";

describe("Merkle test suite.", () => {
  test("Merkle root calculation works.", async () => {
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

  test("Merkle proof should be able to recalculate Merkle root.", async () => {
    const tree: Uint8Array[] = [];
    const element = new Uint8Array(128);
    const elements = 201;
    const elementIndex = 99;
    const anotherElementIndex = 168;
    for (let i = 0; i < elements; i++) {
      const rand = await dcrypto.randomBytes(128);

      if (i === elementIndex) element.set([...rand]);

      tree.push(rand);
    }

    const root = await dcrypto.getMerkleRoot(tree);

    const proof = await dcrypto.getMerkleProof(tree, tree[elementIndex]);

    const elementHash = await dcrypto.sha512(element);

    const rootCalculated = await dcrypto.getMerkleRootFromProof(
      elementHash,
      proof,
    );

    const anotherProof = await dcrypto.getMerkleProof(
      tree,
      tree[anotherElementIndex],
    );

    const anotherElementHash = await dcrypto.sha512(tree[anotherElementIndex]);

    const anotherRootCalculated = await dcrypto.getMerkleRootFromProof(
      anotherElementHash,
      anotherProof,
    );

    expect(root).toStrictEqual(rootCalculated);
    expect(rootCalculated).toStrictEqual(anotherRootCalculated);

    proof[dcrypto.constants.crypto_hash_sha512_BYTES] = 2;
    await expect(
      dcrypto.getMerkleRootFromProof(elementHash, proof),
    ).rejects.toThrow("Proof artifact position is neither left nor right.");
  });

  test("Merkle proof verification works for odd number of elements.", async () => {
    const tree: Uint8Array[] = [];
    const element = new Uint8Array(128);
    const elements = 201;
    const elementIndex = 139;
    for (let i = 0; i < elements; i++) {
      const rand = await dcrypto.randomBytes(128);

      if (i === elementIndex) element.set([...rand]);

      tree.push(rand);
    }

    const root = await dcrypto.getMerkleRoot(tree);

    const proof = await dcrypto.getMerkleProof(tree, tree[elementIndex]);

    const elementHash = await dcrypto.sha512(element);

    const verification = await dcrypto.verifyMerkleProof(
      elementHash,
      root,
      proof,
    );

    expect(verification).toBe(true);
  });

  test("Merkle proof verification works for even number of elements.", async () => {
    const tree: Uint8Array[] = [];
    const element = new Uint8Array(128);
    const elements = 200;
    const elementIndex = 161;
    for (let i = 0; i < elements; i++) {
      const rand = await dcrypto.randomBytes(128);

      if (i === elementIndex) element.set([...rand]);

      tree.push(rand);
    }

    const root = await dcrypto.getMerkleRoot(tree);

    const proof = await dcrypto.getMerkleProof(tree, tree[elementIndex]);

    const elementHash = await dcrypto.sha512(element);

    const verification = await dcrypto.verifyMerkleProof(
      elementHash,
      root,
      proof,
    );

    expect(verification).toBe(true);
  });

  it("Should throw an error when faced with false data.", async () => {
    const tree: Uint8Array[] = [];
    const element = new Uint8Array(128);
    const elements = 201;
    const elementIndex = 99;
    for (let i = 0; i < elements; i++) {
      const rand = await dcrypto.randomBytes(128);

      if (i === elementIndex) element.set([...rand]);

      tree.push(rand);
    }

    const root = await dcrypto.getMerkleRoot(tree);
    const proof = await dcrypto.getMerkleProof(tree, tree[elementIndex]);
    const elementHash = await dcrypto.sha512(element);

    await expect(
      dcrypto.verifyMerkleProof(
        elementHash,
        root,
        proof.slice(0, proof.length - 1),
      ),
    ).rejects.toThrow("Proof length not multiple of hash length + 1.");

    const proofWrongPosition = Uint8Array.from([...proof]);
    proofWrongPosition[dcrypto.constants.crypto_hash_sha512_BYTES] = 2;
    await expect(
      dcrypto.verifyMerkleProof(elementHash, root, proofWrongPosition),
    ).rejects.toThrow("Proof artifact position is neither left nor right.");

    const proofWrongByte = Uint8Array.from([...proof]);
    proofWrongByte[1] = proof[1] === 255 ? 254 : proof[1] + 1;

    const verification = await dcrypto.verifyMerkleProof(
      elementHash,
      root,
      proofWrongByte,
    );

    expect(verification).toBe(false);
  });

  const len = 64;
  const arr1 = new Uint8Array(len);
  const arr2 = new Uint8Array(len);
  arr1.fill(1);
  arr2.fill(2);

  const arr3 = new Uint8Array(len);
  arr3.fill(1);

  const arr4 = new Uint8Array(len);
  arr4.fill(4);

  const arrayOfArrays1: Uint8Array[] = [];
  arrayOfArrays1.push(arr2);
  arrayOfArrays1.push(arr4);
  arrayOfArrays1.push(arr2);

  interface SomeRandomInterface {
    val1: string;
    val2: string;
    val3: string;
  }

  const arr5: SomeRandomInterface = {
    val1: "1",
    val2: "2",
    val3: "3",
  };

  const arr6: SomeRandomInterface = {
    val1: "5",
    val2: "6",
    val3: "7",
  };

  const arr7: SomeRandomInterface = {
    val1: "10",
    val2: "20",
    val3: "30",
  };

  const arrayOfArrays3: SomeRandomInterface[] = [arr5, arr6, arr7];

  const numberToUint8Array = (n: number): Uint8Array => {
    return Uint8Array.of(
      (n & 0xff000000) >> 24,
      (n & 0x00ff0000) >> 16,
      (n & 0x0000ff00) >> 8,
      (n & 0x000000ff) >> 0,
    );
  };

  const someRandomInterfaceSerializer = (item: SomeRandomInterface) => {
    const uint8 = new Uint8Array(4 * 3 * Uint8Array.BYTES_PER_ELEMENT);

    uint8.set(numberToUint8Array(Number(item.val1)));
    uint8.set(
      numberToUint8Array(Number(item.val2)),
      4 * Uint8Array.BYTES_PER_ELEMENT,
    );
    uint8.set(
      numberToUint8Array(Number(item.val3)),
      8 * Uint8Array.BYTES_PER_ELEMENT,
    );

    return uint8;
  };

  it("Should be possible to get Merkle root and proof from non-Uint8 data.", async () => {
    const root = await dcrypto.getMerkleRoot(
      arrayOfArrays3,
      someRandomInterfaceSerializer,
    );

    const arr6Serialized = someRandomInterfaceSerializer(arr6);
    const proof1 = await dcrypto.getMerkleProof(
      arrayOfArrays3,
      arr6Serialized,
      someRandomInterfaceSerializer,
    );

    const arrayOfArrays3Serialized: Uint8Array[] = [];
    for (let i = 0; i < arrayOfArrays3.length; i++) {
      arrayOfArrays3Serialized.push(
        someRandomInterfaceSerializer(arrayOfArrays3[i]),
      );
    }
    const proof2 = await dcrypto.getMerkleProof(
      arrayOfArrays3Serialized,
      arr6,
      someRandomInterfaceSerializer,
    );

    const elementHash = await dcrypto.sha512(arr6Serialized);
    const verification1 = await dcrypto.verifyMerkleProof(
      elementHash,
      root,
      proof1,
    );

    const verification2 = await dcrypto.verifyMerkleProof(
      elementHash,
      root,
      proof2,
    );

    expect(verification1).toBe(true);
    expect(verification2).toBe(true);

    const root1 = await dcrypto.getMerkleRoot(
      [arr6],
      someRandomInterfaceSerializer,
    );
    expect(root1.length).toBe(64);

    const root2 = await dcrypto.getMerkleRoot([arr6Serialized]);
    expect(root2.length).toBe(64);
  });

  it("Should be possible to get Merkle root for one-element arrays.", async () => {
    const proof = await dcrypto.getMerkleProof(
      [arr6],
      arr6,
      someRandomInterfaceSerializer,
    );

    expect(proof).toStrictEqual(
      new Uint8Array(dcrypto.constants.crypto_hash_sha512_BYTES + 1).fill(1),
    );

    const root = await dcrypto.getMerkleRoot(
      [arr6],
      someRandomInterfaceSerializer,
    );

    const arr6Serialized = someRandomInterfaceSerializer(arr6);
    const elementHash = await dcrypto.sha512(arr6Serialized);
    expect(elementHash).toStrictEqual(root);

    const rootFromProof = await dcrypto.getMerkleRootFromProof(
      elementHash,
      proof,
    );
    expect(rootFromProof).toStrictEqual(root);

    const verification = await dcrypto.verifyMerkleProof(
      elementHash,
      root,
      proof,
    );

    expect(verification).toBe(true);
  });

  it("Should throw errors when trying to get merkle root with wrong data.", async () => {
    await expect(
      dcrypto.getMerkleRoot([], someRandomInterfaceSerializer),
    ).rejects.toThrow("Cannot calculate Merkle root of tree with no leaves.");

    await expect(dcrypto.getMerkleRoot([arr6])).rejects.toThrow(
      "Tree leaf not Uint8Array, needs serializer.",
    );

    await expect(dcrypto.getMerkleRoot(arrayOfArrays3)).rejects.toThrow(
      "Tree leaf not Uint8Array, needs serializer.",
    );
  });

  it("Should throw errors when trying to get merkle proof with wrong data.", async () => {
    await expect(
      dcrypto.getMerkleProof([], arr6, someRandomInterfaceSerializer),
    ).rejects.toThrow(
      "Cannot calculate Merkle proof of element of empty tree.",
    );

    await expect(dcrypto.getMerkleProof(arrayOfArrays3, arr6)).rejects.toThrow(
      "It is mandatory to provide a serializer for non-Uint8Array items",
    );
  });
});
