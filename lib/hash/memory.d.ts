declare const _default: {
    sha512Memory: (arrayLen: number) => WebAssembly.Memory;
    merkleRootMemory: (maxDataLen: number) => {
        initialMemory: WebAssembly.Memory;
        subsequentMemory: WebAssembly.Memory;
    };
};
export default _default;
//# sourceMappingURL=memory.d.ts.map