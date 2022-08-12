declare const _default: {
    keyPair: {
        newKeyPair: (module?: import("../c/build/dcryptoMethodsModule").DCryptoMethodsModule | undefined) => Promise<import("../utils/interfaces").SignKeyPair>;
        keyPairFromSeed: (seed: Uint8Array, module?: import("../c/build/dcryptoMethodsModule").DCryptoMethodsModule | undefined) => Promise<import("../utils/interfaces").SignKeyPair>;
        keyPairFromSecretKey: (secretKey: Uint8Array, module?: import("../c/build/dcryptoMethodsModule").DCryptoMethodsModule | undefined) => Promise<import("../utils/interfaces").SignKeyPair>;
    };
    sign: (message: Uint8Array, secretKey: Uint8Array, module?: import("../c/build/dcryptoMethodsModule").DCryptoMethodsModule | undefined) => Promise<Uint8Array>;
    verify: (message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array, module?: import("../c/build/dcryptoMethodsModule").DCryptoMethodsModule | undefined) => Promise<boolean>;
    encrypt: (message: Uint8Array, publicKey: Uint8Array, additionalData: Uint8Array, module?: import("../c/build/dcryptoMethodsModule").DCryptoMethodsModule | undefined) => Promise<Uint8Array>;
    decrypt: (encrypted: Uint8Array, secretKey: Uint8Array, additionalData: Uint8Array, module?: import("../c/build/dcryptoMethodsModule").DCryptoMethodsModule | undefined) => Promise<Uint8Array>;
    memory: {
        newKeyPairMemory: () => WebAssembly.Memory;
        keyPairFromSeedMemory: () => WebAssembly.Memory;
        keyPairFromSecretKeyMemory: () => WebAssembly.Memory;
        signMemory: (messageLen: number) => WebAssembly.Memory;
        verifyMemory: (messageLen: number) => WebAssembly.Memory;
        encryptMemory: (messageLen: number, additionalDataLen: number) => WebAssembly.Memory;
        decryptMemory: (encryptedLen: number, additionalDataLen: number) => WebAssembly.Memory;
    };
};
export default _default;
//# sourceMappingURL=index.d.ts.map