const bench = require("nanobench");
const crypto = require("crypto");
const dcrypto = require("../../lib/index.cjs");
const nacl = require("tweetnacl");

const times = 10000;

const data = [];
for (let i = 0; i < times; i++) {
  data.push(nacl.randomBytes(256));
}

bench(`X25519 e2e encrypt/decrypt native crypto ${times} times`, (b) => {
  b.start();

  const aliceKeyPair = crypto.generateKeyPairSync("x25519");
  const alicePubExport = aliceKeyPair.publicKey.export({
    type: "spki",
    format: "pem",
  });

  const bobKeyPair = crypto.generateKeyPairSync("x25519");
  const bobPubExport = bobKeyPair.publicKey.export({
    type: "spki",
    format: "pem",
  });

  const bobKeyAgree = crypto.diffieHellman({
    publicKey: crypto.createPublicKey(alicePubExport),
    privateKey: bobKeyPair.privateKey,
  });

  const aliceKeyAgree = crypto.diffieHellman({
    publicKey: crypto.createPublicKey(bobPubExport),
    privateKey: aliceKeyPair.privateKey,
  });

  const nonce = new Uint8Array(12).fill(2);

  for (let i = 0; i < times; i++) {
    const cipher = crypto.createCipheriv(
      "chacha20-poly1305",
      bobKeyAgree,
      nonce,
      {
        authTagLength: 16,
      },
    );
    const ciphertext = cipher.update(data[i]);
    cipher.final();
    const tag = cipher.getAuthTag();

    // Now transmit { ciphertext, nonce, tag }.

    const decipher = crypto.createDecipheriv(
      "chacha20-poly1305",
      aliceKeyAgree,
      nonce,
      {
        authTagLength: 16,
      },
    );
    decipher.setAuthTag(tag);
    decipher.update(ciphertext, "binary");

    try {
      decipher.final();
    } catch (err) {
      throw new Error("Authentication failed!", { cause: err });
    }
  }

  b.end();
});

bench(`X25519 @deliberative/crypto ${times} times`, async (b) => {
  b.start();
  const aliceKeyPair = await dcrypto.keyPair();
  const bobKeyPair = await dcrypto.keyPair();

  const wasmEncryptMemory = dcrypto.loadWasmMemory.encryptForwardSecret(
    256,
    64,
  );
  const wasmEncryptModule = await dcrypto.loadWasmModule({
    wasmMemory: wasmEncryptMemory,
  });

  const wasmDecryptMemory = dcrypto.loadWasmMemory.decryptForwardSecret(
    5000,
    64,
  );
  const wasmDecryptModule = await dcrypto.loadWasmModule({
    wasmMemory: wasmDecryptMemory,
  });

  const additional = new Uint8Array(64).fill(2);
  for (let i = 0; i < times; i++) {
    const encryptedWithModule = await dcrypto.encrypt(
      data[i],
      bobKeyPair.publicKey,
      aliceKeyPair.secretKey,
      additional,
      wasmEncryptModule,
    );

    const _decryptedWithModule = await dcrypto.decrypt(
      encryptedWithModule,
      aliceKeyPair.publicKey,
      bobKeyPair.secretKey,
      additional,
      wasmDecryptModule,
    );
  }

  b.end();
});

bench(`X25519 tweetnacl ${times} times`, (b) => {
  b.start();

  const aliceKeyPair = nacl.box.keyPair();
  const bobKeyPair = nacl.box.keyPair();

  const nonce = new Uint8Array(nacl.box.nonceLength).fill(2);

  for (let i = 0; i < times; i++) {
    const box = nacl.box(
      data[i],
      nonce,
      aliceKeyPair.publicKey,
      bobKeyPair.secretKey,
    );

    const open = nacl.box.open(
      box,
      nonce,
      bobKeyPair.publicKey,
      aliceKeyPair.secretKey,
    );
  }

  b.end();
});
