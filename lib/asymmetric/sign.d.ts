import type { DCryptoMethodsModule } from "../c/build/dcryptoMethodsModule";
/**
 * @function
 * Returns the signature of the data provided.
 */
declare const sign: (message: Uint8Array, secretKey: Uint8Array, module?: DCryptoMethodsModule) => Promise<Uint8Array>;
export default sign;
//# sourceMappingURL=sign.d.ts.map