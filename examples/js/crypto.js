import dcrypto from "../../lib";

const main = async () => {
  // Words from dictionary create random seed for Ed25519 private key.
  const mnemonic = await dcrypto.generateMnemonic();

  console.log(mnemonic);

  // Keypair is an object representing an Ed25519 keypair with { publicKey: Uint8Array(32), secretKey: Uint8Array(64) }
  const keypair = await dcrypto.keyPairFromMnemonic(mnemonic);

  console.log(keypair.secretKey);

  // Random Uint8Array array of 128 elements
  const message = await dcrypto.randomBytes(128);

  console.log(message);

  // Can also provide mnemonic instead of private key
  const signature = await dcrypto.sign(message, keypair.secretKey);

  const verify = await dcrypto.verify(message, signature, keypair.publicKey);

  console.log(verify); // true

  const hash = await dcrypto.sha512(message);

  const keypair2 = await dcrypto.keyPair();

  console.log(keypair2.secretKey);

  const encrypted = await dcrypto.encrypt(message, keypair2.publicKey, hash);

  console.log(encrypted);

  const decrypted = await dcrypto.decrypt(encrypted, keypair2.secretKey, hash);

  console.log(decrypted);
};

main();
