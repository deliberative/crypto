declare const _default: {
    sha512: (data: Uint8Array, module?: import("../c/build/dcryptoMethodsModule").DCryptoMethodsModule | undefined) => Promise<Uint8Array>;
    getMerkleRoot: (tree: Uint8Array[]) => Promise<Uint8Array>;
    memory: {
        sha512Memory: (arrayLen: number) => WebAssembly.Memory;
        merkleRootMemory: (maxDataLen: number) => {
            initialMemory: WebAssembly.Memory;
            subsequentMemory: WebAssembly.Memory;
        };
    };
};
export default _default;
//# sourceMappingURL=index.d.ts.map