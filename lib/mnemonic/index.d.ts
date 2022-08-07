declare const _default: {
    generateMnemonic: (strength?: 256 | 128 | 160 | 192 | 224 | undefined) => Promise<string>;
    validateMnemonic: (mnemonic: string) => Promise<boolean>;
    keyPairFromMnemonic: (mnemonic: string) => Promise<import("../utils/interfaces").SignKeyPair>;
};
export default _default;
//# sourceMappingURL=index.d.ts.map