declare const _default: {
    newKeyPairMemory: () => WebAssembly.Memory;
    keyPairFromSeedMemory: () => WebAssembly.Memory;
    keyPairFromSecretKeyMemory: () => WebAssembly.Memory;
    signMemory: (messageLen: number) => WebAssembly.Memory;
    verifyMemory: (messageLen: number) => WebAssembly.Memory;
    encryptMemory: (messageLen: number, additionalDataLen: number) => WebAssembly.Memory;
    decryptMemory: (encryptedLen: number, additionalDataLen: number) => WebAssembly.Memory;
};
export default _default;
//# sourceMappingURL=memory.d.ts.map