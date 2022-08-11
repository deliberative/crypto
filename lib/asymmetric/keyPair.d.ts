import type { LibsodiumMethodsModule } from "../../build/libsodiumMethodsModule";
import { SignKeyPair } from "../utils/interfaces";
declare const _default: {
    newKeyPair: (module?: LibsodiumMethodsModule | undefined) => Promise<SignKeyPair>;
    keyPairFromSeed: (seed: Uint8Array, module?: LibsodiumMethodsModule | undefined) => Promise<SignKeyPair>;
    keyPairFromSecretKey: (secretKey: Uint8Array, module?: LibsodiumMethodsModule | undefined) => Promise<SignKeyPair>;
};
export default _default;
//# sourceMappingURL=keyPair.d.ts.map