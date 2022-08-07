/**
 * Generates a sequence of words that represents a random seed that
 * can be translated into a cryptographic keypair.
 */
declare const generateMnemonic: (strength?: 128 | 160 | 192 | 224 | 256) => Promise<string>;
export default generateMnemonic;
//# sourceMappingURL=generateMnemonic.d.ts.map