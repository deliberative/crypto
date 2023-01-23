#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "../../libsodium/src/libsodium/randombytes/sysrandom/randombytes_sysrandom.c"
#include "../../libsodium/src/libsodium/sodium/runtime.c"

#include "../../src/c/dcrypto.c"

int
main()
{
  int res;

  const unsigned int DATA_LEN = crypto_sign_ed25519_SEEDBYTES;
  uint8_t *random_array = malloc(DATA_LEN);

  res = random_bytes(DATA_LEN, random_array);
  if (res != 0)
  {
    free(random_array);

    printf("Could not generate random data\n");

    return -1;
  }

  uint8_t *hash = malloc(crypto_hash_sha512_BYTES);
  res = sha512(DATA_LEN, random_array, hash);
  if (res != 0)
  {
    free(random_array);
    free(hash);

    printf("Could not calculate SHA512 hash of data\n");

    return -1;
  }

  uint8_t *ed25519_pk = malloc(crypto_sign_ed25519_PUBLICKEYBYTES);
  uint8_t *ed25519_sk = sodium_malloc(crypto_sign_ed25519_SECRETKEYBYTES);
  res = new_keypair(ed25519_pk, ed25519_sk);
  if (res != 0)
  {
    free(random_array);
    free(hash);
    free(ed25519_pk);
    sodium_free(ed25519_sk);

    printf("Could not generate Ed25519 keypair from new_keypair function\n");

    return -1;
  }

  res = keypair_from_seed(ed25519_pk, ed25519_sk, random_array);
  if (res != 0)
  {
    free(random_array);
    free(hash);
    free(ed25519_pk);
    sodium_free(ed25519_sk);

    printf(
        "Could not generate Ed25519 keypair from keypair_from_seed function\n");

    return -1;
  }

  res = keypair_from_secret_key(ed25519_pk, ed25519_sk);
  if (res != 0)
  {
    free(random_array);
    free(hash);
    free(ed25519_pk);
    sodium_free(ed25519_sk);

    printf("Could not generate Ed25519 keypair from keypair_from_secret_key "
           "function\n");

    return -1;
  }

  uint8_t *sig = malloc(crypto_sign_ed25519_BYTES);
  res = sign_data(DATA_LEN, random_array, sig, ed25519_sk);
  if (res != 0)
  {
    free(random_array);
    free(hash);
    free(ed25519_pk);
    sodium_free(ed25519_sk);
    free(sig);

    printf("Could not generate Ed25519 signature\n");

    return -1;
  }

  int verified = verify_data(DATA_LEN, random_array, sig, ed25519_pk);
  if (verified != 0)
  {
    free(random_array);
    free(hash);
    free(ed25519_pk);
    sodium_free(ed25519_sk);
    free(sig);

    printf("Could not verify signed data\n");

    return -1;
  }

  uint8_t *another_ed25519_pk = malloc(crypto_sign_ed25519_PUBLICKEYBYTES);
  uint8_t *another_ed25519_sk
      = sodium_malloc(crypto_sign_ed25519_SECRETKEYBYTES);
  crypto_sign_ed25519_keypair(another_ed25519_pk, another_ed25519_sk);

  int ENCRYPTED_LEN = crypto_scalarmult_curve25519_BYTES
                      + crypto_aead_chacha20poly1305_ietf_NPUBBYTES + DATA_LEN
                      + crypto_aead_chacha20poly1305_ietf_ABYTES;
  uint8_t *encrypted = malloc(ENCRYPTED_LEN);
  forward_secretbox_encrypt_data(DATA_LEN, random_array, another_ed25519_pk,
                                 crypto_hash_sha512_BYTES, hash, encrypted);

  uint8_t *decrypted = malloc(DATA_LEN);
  uint8_t verified_2 = forward_secretbox_decrypt_data(
      ENCRYPTED_LEN, encrypted, another_ed25519_sk, crypto_hash_sha512_BYTES,
      hash, decrypted);
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

  free(hash);
  free(ed25519_pk);
  sodium_free(ed25519_sk);
  free(sig);

  free(another_ed25519_pk);
  sodium_free(another_ed25519_sk);
  free(encrypted);
  free(decrypted);

  int SHARES_LEN = 255;
  int THRESHOLD = 101;

  uint8_t(*shares)[DATA_LEN + 1]
      = malloc(sizeof(uint8_t[SHARES_LEN][DATA_LEN + 1]));

  split_secret(SHARES_LEN, THRESHOLD, DATA_LEN, random_array, shares);

  uint8_t *restored = malloc(DATA_LEN);

  restore_secret(SHARES_LEN, DATA_LEN, shares, restored);

  for (size_t i = 0; i < DATA_LEN; i++)
  {
    if (restored[i] != random_array[i])
    {
      free(random_array);
      free(restored);
      free(shares);

      printf("Could not restore secret at index %zu, restored was %d while "
             "original was %d\n",
             i, restored[i], random_array[i]);

      return -1;
    }
  }

  free(restored);

  uint8_t(*merkle_leaves)[crypto_hash_sha512_BYTES]
      = malloc(sizeof(uint8_t[SHARES_LEN][crypto_hash_sha512_BYTES]));
  uint8_t *leaf_hash = malloc(crypto_hash_sha512_BYTES);
  for (size_t i = 0; i < SHARES_LEN; i++)
  {
    res = sha512(DATA_LEN + 1, shares[i], leaf_hash);
    if (res != 0)
    {
      free(leaf_hash);
      free(random_array);
      free(merkle_leaves);
      free(shares);

      printf("Could not calculate SHA512 hash of each share\n");

      return -1;
    }

    memcpy(&merkle_leaves[i][0], &leaf_hash[0], crypto_hash_sha512_BYTES);
  }

  free(leaf_hash);

  uint8_t *merkle_root = malloc(crypto_hash_sha512_BYTES);
  res = get_merkle_root(SHARES_LEN, merkle_leaves, merkle_root);
  if (res != 0)
  {
    free(random_array);
    free(merkle_leaves);
    free(merkle_root);
    free(shares);

    printf("Could not calculate Merkle root of shares\n");

    return -1;
  }

  size_t leaf_index = 128; // SHARES_LEN - 63;

  uint8_t(*merkle_proof_full)[crypto_hash_sha512_BYTES + 1]
      = malloc(sizeof(uint8_t[SHARES_LEN][crypto_hash_sha512_BYTES + 1]));
  res = get_merkle_proof(SHARES_LEN, merkle_leaves, merkle_leaves[leaf_index],
                         merkle_proof_full);
  if (res < 0)
  {
    free(random_array);
    free(merkle_leaves);
    free(merkle_root);
    free(merkle_proof_full);
    free(shares);

    printf("Could not calculate merkle proof of last share. Result was %d\n",
           res);

    return -1;
  }

  unsigned int PROOF_ARTIFACTS_LEN = res / (crypto_hash_sha512_BYTES + 1);

  uint8_t(*merkle_proof)[crypto_hash_sha512_BYTES + 1] = malloc(
      sizeof(uint8_t[PROOF_ARTIFACTS_LEN][crypto_hash_sha512_BYTES + 1]));
  memcpy(&merkle_proof[0][0], &merkle_proof_full[0][0], res);
  free(merkle_proof_full);

  res = verify_merkle_proof(PROOF_ARTIFACTS_LEN, merkle_leaves[leaf_index],
                            merkle_root, merkle_proof);
  if (res != 0)
  {
    free(random_array);
    free(merkle_leaves);
    free(merkle_root);
    free(merkle_proof);
    free(shares);

    printf("Could not verify merkle proof 1. Result was %d\n", res);

    return -1;
  }

  uint8_t *merkle_root_verification = malloc(crypto_hash_sha512_BYTES);
  get_merkle_root_from_proof(PROOF_ARTIFACTS_LEN, merkle_leaves[leaf_index],
                             merkle_proof, merkle_root_verification);

  // For double check
  uint8_t(*merkle_proof_full_1)[crypto_hash_sha512_BYTES + 1]
      = malloc(sizeof(uint8_t[SHARES_LEN][crypto_hash_sha512_BYTES + 1]));
  res = get_merkle_proof(SHARES_LEN, merkle_leaves,
                         merkle_leaves[leaf_index + 1], merkle_proof_full_1);
  unsigned int PROOF_ARTIFACTS_LEN_2 = res / (crypto_hash_sha512_BYTES + 1);
  uint8_t(*merkle_proof_1)[crypto_hash_sha512_BYTES + 1] = malloc(
      sizeof(uint8_t[PROOF_ARTIFACTS_LEN_2][crypto_hash_sha512_BYTES + 1]));
  memcpy(&merkle_proof_1[0][0], &merkle_proof_full_1[0][0], res);
  free(merkle_proof_full_1);
  uint8_t *merkle_root_verification_1 = malloc(crypto_hash_sha512_BYTES);
  get_merkle_root_from_proof(PROOF_ARTIFACTS_LEN_2,
                             merkle_leaves[leaf_index + 1], merkle_proof_1,
                             merkle_root_verification_1);
  free(merkle_proof_1);

  int j;
  for (j = 0; j < crypto_hash_sha512_BYTES; j++)
  {
    if (merkle_root_verification[j] != merkle_root_verification_1[j])
    {
      free(random_array);
      free(merkle_leaves);
      free(merkle_proof);
      free(merkle_root);
      free(shares);

      printf("Merkle root element in verification position %d is %d and "
             "verification_1 is  %d\n",
             j, merkle_root_verification[j], merkle_root_verification_1[j]);

      free(merkle_root_verification);
      free(merkle_root_verification_1);

      printf("Could not recreate merkle root from proof\n");

      return -1;
    }
  }
  free(merkle_root_verification_1);
  //

  for (int j = 0; j < crypto_hash_sha512_BYTES; j++)
  {
    if (merkle_root_verification[j] != merkle_root[j])
    {
      free(random_array);
      free(merkle_leaves);
      free(merkle_proof);
      free(shares);

      printf("Merkle root element in position %d is %d and verification %d\n",
             j, merkle_root[j], merkle_root_verification[j]);

      free(merkle_root);
      free(merkle_root_verification);

      printf("Could not recreate merkle root from proof\n");

      return -1;
    }
  }

  res = verify_merkle_proof(PROOF_ARTIFACTS_LEN, merkle_leaves[leaf_index],
                            merkle_root, merkle_proof);
  if (res != 0)
  {
    free(random_array);
    free(merkle_leaves);
    free(merkle_root);
    free(merkle_root_verification);
    free(merkle_proof);
    free(shares);

    printf("Could not verify merkle proof 2. Result was %d\n", res);

    return -1;
  }

  free(random_array);
  free(merkle_leaves);
  free(merkle_root);
  free(merkle_root_verification);
  free(merkle_proof);
  free(shares);

  printf("SUCCESS\n");

  return 0;
}
