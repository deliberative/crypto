import * as nacl from "tweetnacl";
import dcrypto from "../../lib";

// Words from dictionary create random seed for Ed25519 private key.
const mnemonic = dcrypto.generateMnemonic();

// Keypair is an object representing an Ed25519 keypair with { publicKey: Uint8Array(32), secretKey: Uint8Array(64) }
const keypair = await dcrypto.keypairFromMnemonic(mnemonic);

// Message can be string, Uint8Array or object.
// Fastest is Uint8Array
const message = "Some message";

// Can also provide mnemonic instead of private key
const signature = await dcrypto.sign(message, keypair.secretKey);

const verify = await dcrypto.verify(message, signature, keypair.publicKey);
console.log(verify); // true

const hash = dcrypto.sha512(message);

const keypair2 = nacl.sign.keyPair();

const messageUint8 = message.toUint8Array();

const encrypted = await dcrypto.encrypt(message, keypair2.publicKey, hash);

const decrypted = await dcrypto.decrypt(encrypted, keypair2.secretKey, hash);

// To test equality for two Uint8Arrays in js you need to check if each of their elements are equal
// The === operator does not work
const areEqual = dcrypto.arraysAreEqual(messageUint8, decrypted);
console.log(areEqual); // true
