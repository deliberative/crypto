import type { DCryptoMethodsModule } from "../c/build/dcryptoMethodsModule";
import { SignKeyPair } from "../utils/interfaces";
declare const _default: {
    newKeyPair: (module?: DCryptoMethodsModule | undefined) => Promise<SignKeyPair>;
    keyPairFromSeed: (seed: Uint8Array, module?: DCryptoMethodsModule | undefined) => Promise<SignKeyPair>;
    keyPairFromSecretKey: (secretKey: Uint8Array, module?: DCryptoMethodsModule | undefined) => Promise<SignKeyPair>;
};
export default _default;
//# sourceMappingURL=keyPair.d.ts.map