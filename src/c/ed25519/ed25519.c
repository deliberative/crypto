#include <stdint.h>

#include "../../../../libsodium/src/libsodium/include/sodium/crypto_sign_ed25519.h"

#include "../../../libsodium/src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c"
#include "../../../libsodium/src/libsodium/crypto_sign/ed25519/ref10/keypair.c"
#include "../../../libsodium/src/libsodium/crypto_sign/ed25519/ref10/open.c"
#include "../../../libsodium/src/libsodium/crypto_sign/ed25519/ref10/sign.c"
#include "../../../libsodium/src/libsodium/crypto_verify/verify.c"

__attribute__((used)) int
new_keypair(uint8_t public_key[crypto_sign_ed25519_PUBLICKEYBYTES],
            uint8_t secret_key[crypto_sign_ed25519_SECRETKEYBYTES])
{
  return crypto_sign_ed25519_keypair(public_key, secret_key);
}

__attribute__((used)) int
keypair_from_seed(uint8_t public_key[crypto_sign_ed25519_PUBLICKEYBYTES],
                  uint8_t secret_key[crypto_sign_ed25519_SECRETKEYBYTES],
                  const uint8_t seed[crypto_sign_ed25519_SEEDBYTES])
{
  return crypto_sign_ed25519_seed_keypair(public_key, secret_key, seed);
}

__attribute__((used)) int
keypair_from_secret_key(
    uint8_t public_key[crypto_sign_ed25519_PUBLICKEYBYTES],
    const uint8_t secret_key[crypto_sign_ed25519_SECRETKEYBYTES])
{
  memcpy(public_key, secret_key + crypto_sign_ed25519_SEEDBYTES,
         crypto_sign_ed25519_PUBLICKEYBYTES);

  return 0;
}

__attribute__((used)) int
sign_data(const int DATA_LEN, const uint8_t data[DATA_LEN],
          uint8_t signature[crypto_sign_ed25519_BYTES],
          const uint8_t secret_key[crypto_sign_ed25519_SECRETKEYBYTES])
{
  unsigned long long SIGNATURE_LEN = crypto_sign_ed25519_BYTES;

  return crypto_sign_ed25519_detached(signature, &SIGNATURE_LEN, data, DATA_LEN,
                                      secret_key);
}

__attribute__((used)) int
verify_data(const int DATA_LEN, const uint8_t data[DATA_LEN],
            const uint8_t signature[crypto_sign_ed25519_BYTES],
            const uint8_t public_key[crypto_sign_ed25519_PUBLICKEYBYTES])
{
  return crypto_sign_ed25519_verify_detached(signature, data, DATA_LEN,
                                             public_key);
}
