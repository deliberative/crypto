#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "../../libsodium/src/libsodium/randombytes/sysrandom/randombytes_sysrandom.c"
#include "../../libsodium/src/libsodium/sodium/runtime.c"

#include "../../src/c/libsodium_methods.c"

int
main()
{
  int DATA_LEN = crypto_sign_ed25519_SEEDBYTES;
  uint8_t *random_array = malloc(DATA_LEN * sizeof(uint8_t));
  int res = random_bytes(DATA_LEN, random_array);
  if (res != 0)
  {
    free(random_array);

    printf("Could not generate random data\n");

    return -1;
  }

  uint8_t *hash = malloc(crypto_hash_sha512_BYTES * sizeof(uint8_t));

  sha512(DATA_LEN, random_array, hash);

  uint8_t *ed25519_pk
      = malloc(crypto_sign_ed25519_PUBLICKEYBYTES * sizeof(uint8_t));
  uint8_t *ed25519_sk
      = sodium_malloc(crypto_sign_ed25519_SECRETKEYBYTES * sizeof(uint8_t));
  new_keypair(ed25519_pk, ed25519_sk);
  keypair_from_seed(ed25519_pk, ed25519_sk, random_array);
  keypair_from_secret_key(ed25519_pk, ed25519_sk);
  uint8_t *sig = malloc(crypto_sign_ed25519_BYTES * sizeof(uint8_t));

  sign_data(DATA_LEN, random_array, sig, ed25519_sk);
  bool verified = verify_data(DATA_LEN, random_array, sig, ed25519_pk);
  if (!verified)
  {
    free(random_array);
    free(hash);
    free(ed25519_pk);
    sodium_free(ed25519_sk);
    free(sig);

    printf("Could not verify signed data\n");

    return -1;
  }

  uint8_t *another_ed25519_pk
      = malloc(crypto_sign_ed25519_PUBLICKEYBYTES * sizeof(uint8_t));
  uint8_t *another_ed25519_sk
      = sodium_malloc(crypto_sign_ed25519_SECRETKEYBYTES * sizeof(uint8_t));
  crypto_sign_ed25519_keypair(another_ed25519_pk, another_ed25519_sk);

  int ENCRYPTED_LEN = crypto_scalarmult_curve25519_BYTES
                      + crypto_aead_chacha20poly1305_ietf_NPUBBYTES + DATA_LEN
                      + crypto_aead_chacha20poly1305_ietf_ABYTES;
  uint8_t *encrypted = malloc(ENCRYPTED_LEN * sizeof(uint8_t));
  encrypt_data(DATA_LEN, random_array, another_ed25519_pk,
               crypto_hash_sha512_BYTES, hash, encrypted);

  uint8_t *decrypted = malloc(DATA_LEN * sizeof(uint8_t));
  uint8_t verified_2
      = decrypt_data(ENCRYPTED_LEN, encrypted, another_ed25519_sk,
                     crypto_hash_sha512_BYTES, hash, decrypted);
  if (verified_2 != 0)
  {
    free(random_array);
    free(hash);
    free(ed25519_pk);
    sodium_free(ed25519_sk);
    free(sig);

    free(another_ed25519_pk);
    sodium_free(another_ed25519_sk);
    free(encrypted);
    free(decrypted);

    printf("Could not decrypt encrypted data\n");

    return -1;
  }

  free(random_array);
  free(hash);
  free(ed25519_pk);
  sodium_free(ed25519_sk);
  free(sig);

  free(another_ed25519_pk);
  sodium_free(another_ed25519_sk);
  free(encrypted);
  free(decrypted);

  printf("SUCCESS\n");

  return 0;
}
