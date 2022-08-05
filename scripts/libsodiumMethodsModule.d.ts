/// <reference types="emscripten" />

export interface LibsodiumMethodsModule extends EmscriptenModule {
  wasmMemory: WebAssembly.Memory;
  _sha512(
    DATA_LEN: number,
    data: number, // Uint8Array, // byteOffset
    hash: number, // Uint8Array
  ): number;
  _random_bytes(
    SIZE: number,
    array: number, // Uint8Array
  ): number;
  _new_keypair(
    public_key: number, // Uint8Array,
    secret_key: number, // Uint8Array
  ): number;
  _keypair_from_seed(
    public_key: number, // Uint8Array,
    secret_key: number, // Uint8Array,
    seed: number, // Uint8Array,
  ): number;
  _keypair_from_secret_key(
    public_key: number, // Uint8Array,
    secret_key: number, // Uint8Array,
  ): number;
  _sign_data(
    DATA_LEN: number,
    data: number, // Uint8Array,
    signature: number, // Uint8Array,
    secret_key: number, // Uint8Array,
  ): number;
  _verify_data(
    DATA_LEN: number,
    data: number, // Uint8Array,
    signature: number, // Uint8Array,
    public_key: number, // Uint8Array,
  ): number;
  _encrypt_data(
    DATA_LEN: number,
    data: number, // Uint8Array,
    public_key: number, // Uint8Array,
    ADDITIONAL_DATA_LEN: number,
    additional_data: number, // Uint8Array,
    encrypted: number, // Uint8Array,
  ): number;
  _decrypt_data(
    ENCRYPTED_LEN: number,
    encrypted_data: number, // Uint8Array,
    secret_key: number, // Uint8Array,
    ADDITIONAL_DATA_LEN: number,
    additional_data: number, // Uint8Array,
    data: number, // Uint8Array,
  ): number;
}

declare const libsodiumMethodsModule: EmscriptenModuleFactory<LibsodiumMethodsModule>;
export default libsodiumMethodsModule;
