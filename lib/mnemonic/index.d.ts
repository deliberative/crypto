declare const _default: {
    generateMnemonic: (strength?: 128 | 160 | 192 | 224 | 256 | undefined) => Promise<string>;
    validateMnemonic: (mnemonic: string) => Promise<boolean>;
    keyPairFromMnemonic: (mnemonic: string) => Promise<import("../utils/interfaces").SignKeyPair>;
};
export default _default;
//# sourceMappingURL=index.d.ts.map