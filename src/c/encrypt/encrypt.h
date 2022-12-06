#ifndef encrypt_H
#define encrypt_H

#include "../../../libsodium/src/libsodium/include/sodium/crypto_aead_chacha20poly1305.h"

void
calculate_nonce(uint8_t nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES]);

#endif
