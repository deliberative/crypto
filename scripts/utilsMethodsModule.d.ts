/// <reference types="emscripten" />

export interface UtilsMethodsModule extends EmscriptenModule {
  wasmMemory: WebAssembly.Memory;
  _random_number_in_range(MIN: number, MAX: number): number;
}

declare const utilsMethodsModule: EmscriptenModuleFactory<UtilsMethodsModule>;
export default utilsMethodsModule;
