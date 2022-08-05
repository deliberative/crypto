/// <reference types="emscripten" />

export interface ShamirMethodsModule extends EmscriptenModule {
  wasmMemory: WebAssembly.Memory;
  _split_secret(
    SHARES_LEN: number,
    THRESHOLD: number,
    SECRET_LEN: number,
    secret: number, // Uint8Array, // byteOffset
    shares: number, // Uint8Array, // byteOffset
  ): number;
  _restore_secret(
    SHARES_LEN: number,
    SECRET_LEN: number,
    shares: number, // Uint8Array,
    secret: number, // Uint8Array,
  ): number;
}

declare const shamirMethodsModule: EmscriptenModuleFactory<ShamirMethodsModule>;
export default shamirMethodsModule;
