import type { LibsodiumMethodsModule } from "../../build/libsodiumMethodsModule";
/**
 * @function
 * Returns the signature of the data provided.
 */
declare const sign: (message: Uint8Array, secretKey: Uint8Array, module?: LibsodiumMethodsModule) => Promise<Uint8Array>;
export default sign;
//# sourceMappingURL=sign.d.ts.map