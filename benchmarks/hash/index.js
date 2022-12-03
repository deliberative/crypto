const bench = require("nanobench");
const crypto = require("crypto");
const dcrypto = require("../../lib/index.cjs");
const nacl = require("tweetnacl");

const times = 10000;

const data = [];
for (let i = 0; i < times; i++) {
  data.push(nacl.randomBytes(256));
}

let _hash;

bench(`sha512 native crypto ${times} times`, (b) => {
  b.start();

  for (let i = 0; i < times; i++) {
    _hash = crypto.createHash("sha512").update(data[i]).digest();
  }

  b.end();
});

bench(`sha512 @deliberative/crypto ${times} times`, async (b) => {
  b.start();

  const wasmMemory = dcrypto.loadWasmMemory.sha512(256);
  const wasmModule = await dcrypto.loadWasmModule({ wasmMemory });

  for (let i = 0; i < times; i++) {
    _hash = await dcrypto.sha512(data[i], wasmModule);
  }

  b.end();
});

bench(`sha512 tweetnacl ${times} times`, (b) => {
  b.start();

  for (let i = 0; i < times; i++) {
    _hash = nacl.hash(data[i]);
  }

  b.end();
});
