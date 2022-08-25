const dcrypto = require("@deliberative/crypto");

const main = async () => {
  try {
    // 12 Words from dictionary create random seed for Ed25519 private key.
    const mnemonic = await dcrypto.generateMnemonic();
    console.log(`Mnemonic with 128bit entropy => 12 words: ${mnemonic}`);
    // 15 Words from dictionary create random seed for Ed25519 private key.
    const mnemonic1 = await dcrypto.generateMnemonic(160);
    console.log(`Mnemonic with 160bit entropy => 15 words: ${mnemonic1}`);
    // 20 Words from dictionary create random seed for Ed25519 private key.
    const mnemonic2 = await dcrypto.generateMnemonic(192);
    console.log(`Mnemonic with 192bit entropy => 18 words: ${mnemonic2}`);
    // 24 Words from dictionary create random seed for Ed25519 private key.
    const mnemonic3 = await dcrypto.generateMnemonic(224);
    console.log(`Mnemonic with 224bit entropy => 21 words: ${mnemonic3}`);
    // 28 Words from dictionary create random seed for Ed25519 private key.
    const mnemonic4 = await dcrypto.generateMnemonic(256);
    console.log(`Mnemonic with 256bit entropy => 24 words: ${mnemonic4}`);

    // Keypair is an object representing an Ed25519 keypair with { publicKey: Uint8Array(32), secretKey: Uint8Array(64) }
    const keypair = await dcrypto.keyPairFromMnemonic(mnemonic);

    console.log(
      `Keypair from mnemonic: {\n\
  secretKey: ${Buffer.from(keypair.secretKey).toString("hex")}\n\
  publicKey: ${Buffer.from(keypair.publicKey).toString("hex")}\n}\
`,
    );

    // Random Uint8Array array of 32 elements
    const message = await dcrypto.randomBytes(32);

    console.log(
      `Random message to sign: ${Buffer.from(message).toString("hex")}`,
    );

    // Can also provide mnemonic instead of private key
    const signature = await dcrypto.sign(message, keypair.secretKey);

    console.log(`Signature: ${Buffer.from(signature).toString("hex")}`);

    const verify = await dcrypto.verify(message, signature, keypair.publicKey);

    console.log(`Verification: ${verify}`); // true

    const hash = await dcrypto.sha512(message);

    console.log(
      `SHA512 of the random message: ${Buffer.from(hash).toString("hex")}`,
    );

    const keypair2 = await dcrypto.keyPair();

    console.log(
      `New random keypair: {\n\
  secretKey: ${Buffer.from(keypair2.secretKey).toString("hex")}\n\
  publicKey: ${Buffer.from(keypair2.publicKey).toString("hex")}\n}\
`,
    );

    const encrypted = await dcrypto.encrypt(message, keypair2.publicKey, hash);

    console.log(
      `AEAD encrypted box for random message and keypair2: ${Buffer.from(
        encrypted,
      ).toString("hex")}`,
    );

    const decrypted = await dcrypto.decrypt(
      encrypted,
      keypair2.secretKey,
      hash,
    );

    console.log(
      `Decrypted AEAD box should be equal to random message: \n\
  Decrypted: ${Buffer.from(decrypted).toString("hex")} \n\
  Original : ${Buffer.from(message).toString("hex")}\n`,
    );
  } catch (err) {
    console.error(err);
  }
};

main();
