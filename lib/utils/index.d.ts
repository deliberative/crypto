declare const _default: {
    randomBytes: (n: number, module?: import("../c/build/dcryptoMethodsModule").DCryptoMethodsModule | undefined) => Promise<Uint8Array>;
    randomNumberInRange: (min: number, max: number, module?: import("../c/build/dcryptoMethodsModule").DCryptoMethodsModule | undefined) => Promise<number>;
    arrayRandomShuffle: <T>(array: T[]) => Promise<T[]>;
    arrayRandomSubset: <T_1>(array: T_1[], elements: number) => Promise<T_1[]>;
    memory: {
        randomBytesMemory: (bytes: number) => WebAssembly.Memory;
        randomNumberInRangeMemory: (min: number, max: number) => WebAssembly.Memory;
    };
};
export default _default;
//# sourceMappingURL=index.d.ts.map