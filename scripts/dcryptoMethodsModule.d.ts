/// <reference types="emscripten" />

export interface DCryptoMethodsModule extends EmscriptenModule {
  wasmMemory: WebAssembly.Memory;

  _sha512(
    DATA_LEN: number,
    data: number, // Uint8Array, // byteOffset
    hash: number, // Uint8Array
  ): number;
  _argon2(
    MNEMONIC_LEN: number,
    seed: number, // Uint8Array
    mnemonic: number, // Int8Array
    salt: number, // Uint8Array
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
    key: number, // Uint8Array,
    ADDITIONAL_DATA_LEN: number,
    additional_data: number, // Uint8Array,
    encrypted: number, // Uint8Array,
  ): number;
  _decrypt_data(
    ENCRYPTED_LEN: number,
    encrypted_data: number, // Uint8Array,
    key: number, // Uint8Array,
    ADDITIONAL_DATA_LEN: number,
    additional_data: number, // Uint8Array,
    data: number, // Uint8Array,
  ): number;

  _forward_secretbox_encrypt_data(
    DATA_LEN: number,
    data: number, // Uint8Array,
    public_key: number, // Uint8Array,
    ADDITIONAL_DATA_LEN: number,
    additional_data: number, // Uint8Array,
    encrypted: number, // Uint8Array,
  ): number;
  _forward_secretbox_decrypt_data(
    ENCRYPTED_LEN: number,
    encrypted_data: number, // Uint8Array,
    secret_key: number, // Uint8Array,
    ADDITIONAL_DATA_LEN: number,
    additional_data: number, // Uint8Array,
    data: number, // Uint8Array,
  ): number;

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

  _item_index_in_array(
    ARRAY_LEN: number,
    array: number, // Uint8Array byteOffset
    item: number, // Uint8Array byteOffset
  ): number;
  _items_indexes_in_array(
    ARRAY_LEN: number,
    ITEMS_ARRAY_LEN: number,
    array: number, // Uint8Array byteOffset
    items: number, // Uint8Array byteOffset
    indexes: number, // Array byteOffset
  ): void;
  _random_bytes(
    SIZE: number,
    array: number, // Uint8Array
  ): number;
  _random_number_in_range(MIN: number, MAX: number): number;
}

declare const dcryptoMethodsModule: EmscriptenModuleFactory<DCryptoMethodsModule>;
export default dcryptoMethodsModule;
