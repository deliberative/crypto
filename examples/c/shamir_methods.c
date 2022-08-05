#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "../../libsodium/src/libsodium/randombytes/sysrandom/randombytes_sysrandom.c"
#include "../../libsodium/src/libsodium/sodium/core.c"
#include "../../libsodium/src/libsodium/sodium/runtime.c"
#include "../../libsodium/src/libsodium/sodium/utils.c"

// SHA512
#include "../../libsodium/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c"

// Ed25519
#include "../../libsodium/src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c"
#include "../../libsodium/src/libsodium/crypto_sign/ed25519/ref10/keypair.c"
#include "../../libsodium/src/libsodium/crypto_sign/ed25519/ref10/open.c"
#include "../../libsodium/src/libsodium/crypto_sign/ed25519/ref10/sign.c"
#include "../../libsodium/src/libsodium/crypto_verify/sodium/verify.c"

// AEAD Chacha20Poly1305
#include "../../libsodium/src/libsodium/crypto_aead/chacha20poly1305/sodium/aead_chacha20poly1305.c"
#include "../../libsodium/src/libsodium/crypto_generichash/blake2b/ref/blake2b-compress-ref.c"
#include "../../libsodium/src/libsodium/crypto_generichash/blake2b/ref/blake2b-ref.c"
#include "../../libsodium/src/libsodium/crypto_generichash/blake2b/ref/generichash_blake2b.c"
#include "../../libsodium/src/libsodium/crypto_generichash/crypto_generichash.c"
#include "../../libsodium/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna.c"
#include "../../libsodium/src/libsodium/crypto_onetimeauth/poly1305/onetimeauth_poly1305.c"
#include "../../libsodium/src/libsodium/crypto_stream/chacha20/ref/chacha20_ref.c"
#include "../../libsodium/src/libsodium/crypto_stream/chacha20/stream_chacha20.c"

// Diffie Hellman
#include "../../libsodium/src/libsodium/crypto_kx/crypto_kx.c"
#include "../../libsodium/src/libsodium/crypto_scalarmult/crypto_scalarmult.c"
#include "../../libsodium/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c"
#include "../../libsodium/src/libsodium/crypto_scalarmult/curve25519/scalarmult_curve25519.c"
#include "../../libsodium/src/libsodium/crypto_scalarmult/ed25519/ref10/scalarmult_ed25519_ref10.c"

#include "../../src/c/shamir_methods.c"

int
main()
{
  size_t i;

  int SECRET_LEN = 64;
  uint8_t *secret = malloc(SECRET_LEN * sizeof(uint8_t));

  for (i = 0; i < SECRET_LEN; i++)
  {
    secret[i] = i;
  }

  int SHARES_LEN = 200;
  int THRESHOLD = 101;

  uint8_t *shares = malloc(SHARES_LEN * (SECRET_LEN + 1) * sizeof(uint8_t));

  split_secret(SHARES_LEN, THRESHOLD, SECRET_LEN, secret, shares);

  uint8_t *restored = malloc(SECRET_LEN * sizeof(uint8_t));

  restore_secret(SHARES_LEN, SECRET_LEN, shares, restored);

  for (size_t i = 0; i < SECRET_LEN; i++)
  {
    if (restored[i] != secret[i])
    {
      free(restored);
      free(secret);
      free(shares);

      printf("Could not restore secret \n");

      return -1;
    }
  }

  free(restored);
  free(secret);
  free(shares);

  printf("SUCCESS\n");

  return 0;
}
