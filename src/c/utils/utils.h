#ifndef utils_H
#define utils_H

#include <stddef.h>
#include <stdint.h>

#include "../../../libsodium/src/libsodium/include/sodium/crypto_hash_sha512.h"

void items_indexes_in_array(
    const unsigned int ARRAY_LEN, const unsigned int ITEMS_ARRAY_LEN,
    const uint8_t array[ARRAY_LEN][crypto_hash_sha512_BYTES],
    const uint8_t items[ITEMS_ARRAY_LEN][crypto_hash_sha512_BYTES],
    int32_t indexes[ITEMS_ARRAY_LEN]);

int random_bytes(const unsigned int SIZE, uint8_t array[SIZE]);

#endif
