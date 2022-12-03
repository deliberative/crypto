const bench = require("nanobench");
const crypto = require("crypto");
const dcrypto = require("../../lib/index.cjs");
const nacl = require("tweetnacl");

const times = 10000;

const data = [];
for (let i = 0; i < times; i++) {
  data.push(nacl.randomBytes(256));
}

let signature;
let _verification;

const keyPair = nacl.sign.keyPair();

bench(`Ed25519 sign/verify native crypto ${times} times`, (b) => {
  b.start();

  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");

  for (let i = 0; i < times; i++) {
    signature = crypto.sign(null, data[i], privateKey);
    _verification = crypto.verify(null, data[i], publicKey, signature);
  }

  b.end();
});

bench(`Ed25519 @deliberative/crypto ${times} times`, async (b) => {
  b.start();

  const wasmSignMemory = dcrypto.loadWasmMemory.sign(256);
  const wasmSignModule = await dcrypto.loadWasmModule({
    wasmMemory: wasmSignMemory,
  });

  const wasmVerifyMemory = dcrypto.loadWasmMemory.verify(256);
  const wasmVerifyModule = await dcrypto.loadWasmModule({
    wasmMemory: wasmVerifyMemory,
  });

  for (let i = 0; i < times; i++) {
    signature = await dcrypto.sign(data[i], keyPair.secretKey, wasmSignModule);
    _verification = await dcrypto.verify(
      data[i],
      signature,
      keyPair.publicKey,
      wasmVerifyModule,
    );
  }

  b.end();
});

bench(`Ed25519 tweetnacl ${times} times`, (b) => {
  b.start();

  for (let i = 0; i < times; i++) {
    signature = nacl.sign.detached(data[i], keyPair.secretKey);
    _verification = nacl.sign.detached.verify(
      data[i],
      signature,
      keyPair.publicKey,
    );
  }

  b.end();
});
