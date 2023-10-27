#include "../../../../libsodium/src/libsodium/include/sodium/crypto_scalarmult_curve25519.h"

#include "./x25519_ref10.c"

int
crypto_scalarmult_curve25519(unsigned char *q, const unsigned char *n,
                             const unsigned char *p)
{
  size_t i;
  volatile unsigned char d = 0;

  if (crypto_scalarmult_curve25519_ref10(q, n, p) != 0)
  {
    return -1; /* LCOV_EXCL_LINE */
  }
  for (i = 0; i < crypto_scalarmult_curve25519_BYTES; i++)
  {
    d |= q[i];
  }
  return -(1 & ((d - 1) >> 8));
}

int
crypto_scalarmult_curve25519_base(unsigned char *q, const unsigned char *n)
{
  return crypto_scalarmult_curve25519_ref10_base(q, n);
}

size_t
crypto_scalarmult_curve25519_bytes(void)
{
  return crypto_scalarmult_curve25519_BYTES;
}

size_t
crypto_scalarmult_curve25519_scalarbytes(void)
{
  return crypto_scalarmult_curve25519_SCALARBYTES;
}
