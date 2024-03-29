#include "../../../libsodium/src/libsodium/crypto_aead/chacha20poly1305/aead_chacha20poly1305.c"
#include "../../../libsodium/src/libsodium/crypto_generichash/blake2b/ref/blake2b-ref.c"
#include "../../../libsodium/src/libsodium/crypto_generichash/blake2b/ref/generichash_blake2b.c"
#include "../../../libsodium/src/libsodium/crypto_generichash/crypto_generichash.c"
#include "../../../libsodium/src/libsodium/crypto_stream/chacha20/ref/chacha20_ref.c"
#include "../../../libsodium/src/libsodium/crypto_stream/chacha20/stream_chacha20.c"
#include "./crypto_generichash/blake2b-compress-ref.c"
#include "./poly1305/onetimeauth_poly1305.c"

// // Diffie Hellman
#include "../../../libsodium/src/libsodium/crypto_kx/crypto_kx.c"
#include "../../../libsodium/src/libsodium/crypto_scalarmult/crypto_scalarmult.c"
#include "../../../libsodium/src/libsodium/crypto_scalarmult/ed25519/ref10/scalarmult_ed25519_ref10.c"
#include "./crypto_scalarmult_curve25519/scalarmult_curve25519.c"

#include "./e2e_decrypt_data.c"
#include "./e2e_encrypt_data.c"
#include "./forward_secretbox_decrypt.c"
#include "./forward_secretbox_encrypt.c"
#include "./key_decrypt_data.c"
#include "./key_encrypt_data.c"
