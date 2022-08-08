declare const _default: {
    randomBytes: (n: number, module?: import("../../build/libsodiumMethodsModule").LibsodiumMethodsModule | undefined) => Promise<Uint8Array>;
    randomNumberInRange: (min: number, max: number, module?: import("../../build/utilsMethodsModule").UtilsMethodsModule | undefined) => Promise<number>;
    arrayRandomShuffle: <T>(array: T[]) => Promise<T[]>;
    arrayRandomSubset: <T_1>(array: T_1[], elements: number) => Promise<T_1[]>;
    memory: {
        randomBytesMemory: (bytes: number) => WebAssembly.Memory;
        randomNumberInRangeMemory: (min: number, max: number) => WebAssembly.Memory;
    };
};
export default _default;
//# sourceMappingURL=index.d.ts.map