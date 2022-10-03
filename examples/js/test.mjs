import dcrypto from "@deliberative/crypto";

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

    const encrypted = await dcrypto.encryptForwardSecrecy(
      message,
      keypair2.publicKey,
      hash,
    );

    console.log(
      `AEAD encrypted box for random message and keypair2: ${Buffer.from(
        encrypted,
      ).toString("hex")}`,
    );

    const decrypted = await dcrypto.decryptForwardSecrecy(
      encrypted,
      keypair2.secretKey,
      hash,
    );

    console.log(
      `Decrypted AEAD box should be equal to random message: \n\
      Decrypted: ${Buffer.from(decrypted).toString("hex")} \n\
      Original : ${Buffer.from(message).toString("hex")}\n`,
    );

    const sharesLen = 255;
    const threshold = 165;
    const shares = await dcrypto.splitSecret(
      keypair.secretKey,
      sharesLen,
      threshold,
    );
    console.log(
      `We split secret key ${Buffer.from(keypair.secretKey).toString(
        "hex",
      )} into ${sharesLen} shares and we need at least ${threshold} shares to recreate it`,
    );
    for (let i = 0; i < sharesLen; i++) {
      console.log(
        `Share #${i + 1} is ${Buffer.from(shares[i]).toString("hex")}`,
      );
    }

    // Should be equal to keypair.secretKey
    const sk1 = await dcrypto.restoreSecret(shares);
    console.log(
      `If we combine all shares then the result ${Buffer.from(sk1).toString(
        "hex",
      )} should be equal to secret key ${Buffer.from(
        keypair.secretKey,
      ).toString("hex")}`,
    );

    // Remove 80 shares to see if it will still work
    const lessShares = shares.slice(0, shares.length - 80);
    const lessSharesRandom = await dcrypto.arrayRandomShuffle(lessShares);

    // Should be equal to sk1 and keypair.secretKey
    const sk2 = await dcrypto.restoreSecret(lessSharesRandom);
    console.log(
      `If we combine 60 shares then the result ${Buffer.from(sk2).toString(
        "hex",
      )} should be equal to secret key ${Buffer.from(
        keypair.secretKey,
      ).toString("hex")}`,
    );

    // Remove 11 more and now we are bellow the threshold
    const evenLessShares = await dcrypto.arrayRandomSubset(
      lessShares,
      lessShares.length - 11,
    );

    // Should not be equal to sk1 and sk2.
    const sk3 = await dcrypto.restoreSecret(evenLessShares);
    console.log(
      `If we combine 59 shares then the result ${Buffer.from(sk3).toString(
        "hex",
      )} will be differet from the secret key ${Buffer.from(
        keypair.secretKey,
      ).toString("hex")}`,
    );
  } catch (err) {
    console.error(err);
  }
};

main();
