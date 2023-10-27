#include "./poly1305_donna.c"

int
crypto_onetimeauth_poly1305(unsigned char *out, const unsigned char *in,
                            unsigned long long inlen, const unsigned char *k)
{
  return crypto_onetimeauth_poly1305_donna(out, in, inlen, k);
}

int
crypto_onetimeauth_poly1305_verify(const unsigned char *h,
                                   const unsigned char *in,
                                   unsigned long long inlen,
                                   const unsigned char *k)
{
  return crypto_onetimeauth_poly1305_donna_verify(h, in, inlen, k);
}

int
crypto_onetimeauth_poly1305_init(crypto_onetimeauth_poly1305_state *state,
                                 const unsigned char *key)
{
  return crypto_onetimeauth_poly1305_donna_init(state, key);
}

int
crypto_onetimeauth_poly1305_update(crypto_onetimeauth_poly1305_state *state,
                                   const unsigned char *in,
                                   unsigned long long inlen)
{
  return crypto_onetimeauth_poly1305_donna_update(state, in, inlen);
}

int
crypto_onetimeauth_poly1305_final(crypto_onetimeauth_poly1305_state *state,
                                  unsigned char *out)
{
  return crypto_onetimeauth_poly1305_donna_final(state, out);
}

size_t
crypto_onetimeauth_poly1305_bytes(void)
{
  return crypto_onetimeauth_poly1305_BYTES;
}

size_t
crypto_onetimeauth_poly1305_keybytes(void)
{
  return crypto_onetimeauth_poly1305_KEYBYTES;
}

size_t
crypto_onetimeauth_poly1305_statebytes(void)
{
  return sizeof(crypto_onetimeauth_poly1305_state);
}

void
crypto_onetimeauth_poly1305_keygen(
    unsigned char k[crypto_onetimeauth_poly1305_KEYBYTES])
{
  randombytes_buf(k, crypto_onetimeauth_poly1305_KEYBYTES);
}
