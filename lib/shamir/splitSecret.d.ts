import type { DCryptoMethodsModule } from "../c/build/dcryptoMethodsModule";
declare const splitSecret: (secret: Uint8Array, sharesLen: number, threshold: number, module?: DCryptoMethodsModule) => Promise<Uint8Array[]>;
export default splitSecret;
//# sourceMappingURL=splitSecret.d.ts.map