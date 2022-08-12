/// <reference types="emscripten" />
import type { SignKeyPair } from "./utils/interfaces";
import type { DCryptoMethodsModule } from "./c/build/dcryptoMethodsModule";
export interface DeliberativeCrypto {
    /**
     * Generates a Uint8Array of size n full with random bytes
     */
    randomBytes: (n: number, module?: DCryptoMethodsModule) => Promise<Uint8Array>;
    /**
     * Get an integer between min and max with uniform probability
     */
    randomNumberInRange: (min: number, max: number, module?: DCryptoMethodsModule) => Promise<number>;
    /**
     * Fisher-Yates random shuffle of elements of an array
     */
    arrayRandomShuffle: <T>(array: T[]) => Promise<T[]>;
    /**
     * Fisher-Yates random shuffle then slice of array
     */
    arrayRandomSubset: <T>(array: T[], elements: number) => Promise<T[]>;
    loadUtilsMemory: {
        randomBytes: (bytes: number) => WebAssembly.Memory;
        randomNumberInRange: (min: number, max: number) => WebAssembly.Memory;
    };
    /**
     * Generate a new Ed25519 keypair
     */
    keyPair: (module?: DCryptoMethodsModule) => Promise<SignKeyPair>;
    /**
     * Generate a new Ed25519 keypair from a given seed
     */
    keyPairFromSeed: (seed: Uint8Array, module?: DCryptoMethodsModule) => Promise<SignKeyPair>;
    /**
     * Generate a new Ed25519 keypair from an Ed25519 secret key
     */
    keyPairFromSecretKey: (secretKey: Uint8Array, module?: DCryptoMethodsModule) => Promise<SignKeyPair>;
    /**
     * Generates a digital signature for the message using the private key.
     */
    sign: (message: Uint8Array, secretKey: Uint8Array, module?: DCryptoMethodsModule) => Promise<Uint8Array>;
    /**
     * Verifies that the digital signature was indeed generated from private key
     * corresponding to the public key
     */
    verify: (message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array, module?: DCryptoMethodsModule) => Promise<boolean>;
    /**
     * Encrypts
     */
    encrypt: (message: Uint8Array, publicKey: Uint8Array, additionalData: Uint8Array, module?: DCryptoMethodsModule) => Promise<Uint8Array>;
    /**
     * Decrypts
     */
    decrypt: (encrypted: Uint8Array, secretKey: Uint8Array, additionalData: Uint8Array, module?: DCryptoMethodsModule) => Promise<Uint8Array>;
    /**
     * Generates a 12-natural-language-word representation of an Ed25519 private key.
     */
    generateMnemonic: (strength?: 128 | 160 | 192 | 224 | 256) => Promise<string>;
    /**
     * Validates that a natural-language-word representation of an Ed25519 private key is accurate
     */
    validateMnemonic: (mnemonic: string) => Promise<boolean>;
    /**
     * Generates an Ed25519 keypair from a 12-natural-language-word mnemonic.
     */
    keyPairFromMnemonic: (mnemonic: string, password?: string) => Promise<SignKeyPair>;
    loadAsymmetricMemory: {
        newKeyPair: () => WebAssembly.Memory;
        keyPairFromSeed: () => WebAssembly.Memory;
        keyPairFromSecretKey: () => WebAssembly.Memory;
        sign: (messageLen: number) => WebAssembly.Memory;
        verify: (messageLen: number) => WebAssembly.Memory;
        encrypt: (messageLen: number, additionalDataLen: number) => WebAssembly.Memory;
        decrypt: (encryptedLen: number, additionalDataLen: number) => WebAssembly.Memory;
    };
    sha512: (data: Uint8Array, module?: DCryptoMethodsModule) => Promise<Uint8Array>;
    getMerkleRoot: (tree: Uint8Array[]) => Promise<Uint8Array>;
    loadHashMemory: {
        sha512: (arrayLen: number) => WebAssembly.Memory;
        merkleRoot: (maxDataLen: number) => {
            initialMemory: WebAssembly.Memory;
            subsequentMemory: WebAssembly.Memory;
        };
    };
    splitSecret: (secret: Uint8Array, numberOfShares: number, threshold: number, module?: DCryptoMethodsModule) => Promise<Uint8Array[]>;
    restoreSecret: (shares: Uint8Array[], module?: DCryptoMethodsModule) => Promise<Uint8Array>;
    loadShamirMemory: {
        splitSecret: (secretLen: number, sharesLen: number, threshold: number) => WebAssembly.Memory;
        restoreSecret: (secretLen: number, sharesLen: number) => WebAssembly.Memory;
    };
    loadModule: EmscriptenModuleFactory<DCryptoMethodsModule>;
}
declare const dcrypto: DeliberativeCrypto;
export default dcrypto;
//# sourceMappingURL=index.d.ts.map