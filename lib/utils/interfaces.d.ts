export interface SignKeyPair {
    publicKey: Uint8Array;
    secretKey: Uint8Array;
}
export declare const crypto_hash_sha512_BYTES = 64;
export declare const crypto_secretbox_KEYBYTES = 32;
export declare const crypto_secretbox_NONCEBYTES = 24;
export declare const crypto_box_poly1305_AUTHTAGBYTES = 16;
export declare const crypto_box_x25519_PUBLICKEYBYTES = 32;
export declare const crypto_box_x25519_SECRETKEYBYTES = 32;
export declare const crypto_box_x25519_NONCEBYTES = 12;
export declare const crypto_sign_ed25519_BYTES = 64;
export declare const crypto_sign_ed25519_SEEDBYTES = 32;
export declare const crypto_sign_ed25519_PUBLICKEYBYTES = 32;
export declare const crypto_sign_ed25519_SECRETKEYBYTES = 64;
export declare const crypto_pwhash_argon2id_SALTBYTES = 16;
//# sourceMappingURL=interfaces.d.ts.map