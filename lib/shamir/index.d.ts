declare const _default: {
    splitSecret: (secret: Uint8Array, sharesLen: number, threshold: number, module?: import("../../build/shamirMethodsModule").ShamirMethodsModule | undefined) => Promise<Uint8Array[]>;
    restoreSecret: (shares: Uint8Array[], module?: import("../../build/shamirMethodsModule").ShamirMethodsModule | undefined) => Promise<Uint8Array>;
    memory: {
        splitSecretMemory: (secretLen: number, sharesLen: number, threshold: number) => WebAssembly.Memory;
        restoreSecretMemory: (secretLen: number, sharesLen: number) => WebAssembly.Memory;
    };
};
export default _default;
//# sourceMappingURL=index.d.ts.map