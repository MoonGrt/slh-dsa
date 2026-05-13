#include "ascon.h"

#if defined(ASCON_HASH256) || defined(ASCON_XOF128) || defined(ASCON_AEADXOF128)
int crypto_hash(unsigned char* out, const unsigned char* in,
                unsigned long long len) {
  /* initialize */
  ascon_state_t s;
  s.x[0] = ASCON_INIT;
  s.x[1] = 0;
  s.x[2] = 0;
  s.x[3] = 0;
  s.x[4] = 0;
  P12(&s);

  /* absorb full plaintext blocks */
  while (len >= ASCON_HASH_RATE) {
    s.x[0] ^= LOADBYTES(in, 8);
    P12(&s);
    in += ASCON_HASH_RATE;
    len -= ASCON_HASH_RATE;
  }
  /* absorb final plaintext block */
  s.x[0] ^= LOADBYTES(in, len);
  s.x[0] ^= PAD(len);
  P12(&s);

  /* squeeze full output blocks */
  len = CRYPTO_BYTES;
  while (len > ASCON_HASH_RATE) {
    STOREBYTES(out, s.x[0], 8);
    P12(&s);
    out += ASCON_HASH_RATE;
    len -= ASCON_HASH_RATE;
  }
  /* squeeze final output block */
  STOREBYTES(out, s.x[0], len);

  return 0;
}

#endif

#ifdef ASCON_AEAD128

int crypto_aead_encrypt(unsigned char* c, unsigned long long* clen,
                        const unsigned char* m, unsigned long long mlen,
                        const unsigned char* ad, unsigned long long adlen,
                        const unsigned char* nsec, const unsigned char* npub,
                        const unsigned char* k) {
  (void)nsec;

  /* set ciphertext size */
  *clen = mlen + CRYPTO_ABYTES;

  /* load key and nonce */
  const uint64_t K0 = LOADBYTES(k, 8);
  const uint64_t K1 = LOADBYTES(k + 8, 8);
  const uint64_t N0 = LOADBYTES(npub, 8);
  const uint64_t N1 = LOADBYTES(npub + 8, 8);

  /* initialize */
  ascon_state_t s;
  s.x[0] = ASCON_INIT;
  s.x[1] = K0;
  s.x[2] = K1;
  s.x[3] = N0;
  s.x[4] = N1;
  P12(&s);
  s.x[3] ^= K0;
  s.x[4] ^= K1;

  if (adlen) {
    /* full associated data blocks */
    while (adlen >= ASCON_128A_RATE) {
      s.x[0] ^= LOADBYTES(ad, 8);
      s.x[1] ^= LOADBYTES(ad + 8, 8);
      P8(&s);
      ad += ASCON_128A_RATE;
      adlen -= ASCON_128A_RATE;
    }
    /* final associated data block */
    if (adlen >= 8) {
      s.x[0] ^= LOADBYTES(ad, 8);
      s.x[1] ^= LOADBYTES(ad + 8, adlen - 8);
      s.x[1] ^= PAD(adlen - 8);
    } else {
      s.x[0] ^= LOADBYTES(ad, adlen);
      s.x[0] ^= PAD(adlen);
    }
    P8(&s);
  }
  /* domain separation */
  s.x[4] ^= DSEP();

  /* full plaintext blocks */
  while (mlen >= ASCON_128A_RATE) {
    s.x[0] ^= LOADBYTES(m, 8);
    s.x[1] ^= LOADBYTES(m + 8, 8);
    STOREBYTES(c, s.x[0], 8);
    STOREBYTES(c + 8, s.x[1], 8);
    P8(&s);
    m += ASCON_128A_RATE;
    c += ASCON_128A_RATE;
    mlen -= ASCON_128A_RATE;
  }
  /* final plaintext block */
  if (mlen >= 8) {
    s.x[0] ^= LOADBYTES(m, 8);
    s.x[1] ^= LOADBYTES(m + 8, mlen - 8);
    STOREBYTES(c, s.x[0], 8);
    STOREBYTES(c + 8, s.x[1], mlen - 8);
    s.x[1] ^= PAD(mlen - 8);
  } else {
    s.x[0] ^= LOADBYTES(m, mlen);
    STOREBYTES(c, s.x[0], mlen);
    s.x[0] ^= PAD(mlen);
  }
  m += mlen;
  c += mlen;

  /* finalize */
  s.x[2] ^= K0;
  s.x[3] ^= K1;
  P12(&s);
  s.x[3] ^= K0;
  s.x[4] ^= K1;

  /* get tag */
  STOREBYTES(c, s.x[3], 8);
  STOREBYTES(c + 8, s.x[4], 8);

  return 0;
}


int crypto_aead_decrypt(unsigned char* m, unsigned long long* mlen,
                        unsigned char* nsec, const unsigned char* c,
                        unsigned long long clen, const unsigned char* ad,
                        unsigned long long adlen, const unsigned char* npub,
                        const unsigned char* k) {
  (void)nsec;

  if (clen < CRYPTO_ABYTES) return -1;

  /* set plaintext size */
  *mlen = clen - CRYPTO_ABYTES;

  /* load key and nonce */
  const uint64_t K0 = LOADBYTES(k, 8);
  const uint64_t K1 = LOADBYTES(k + 8, 8);
  const uint64_t N0 = LOADBYTES(npub, 8);
  const uint64_t N1 = LOADBYTES(npub + 8, 8);

  /* initialize */
  ascon_state_t s;
  s.x[0] = ASCON_128A_IV;
  s.x[1] = K0;
  s.x[2] = K1;
  s.x[3] = N0;
  s.x[4] = N1;
  P12(&s);
  s.x[3] ^= K0;
  s.x[4] ^= K1;

  if (adlen) {
    /* full associated data blocks */
    while (adlen >= ASCON_128A_RATE) {
      s.x[0] ^= LOADBYTES(ad, 8);
      s.x[1] ^= LOADBYTES(ad + 8, 8);
      P8(&s);
      ad += ASCON_128A_RATE;
      adlen -= ASCON_128A_RATE;
    }
    /* final associated data block */
    if (adlen >= 8) {
      s.x[0] ^= LOADBYTES(ad, 8);
      s.x[1] ^= LOADBYTES(ad + 8, adlen - 8);
      s.x[1] ^= PAD(adlen - 8);
    } else {
      s.x[0] ^= LOADBYTES(ad, adlen);
      s.x[0] ^= PAD(adlen);
    }
    P8(&s);
  }
  /* domain separation */
  s.x[4] ^= DSEP();

  /* full ciphertext blocks */
  clen -= CRYPTO_ABYTES;
  while (clen >= ASCON_128A_RATE) {
    uint64_t c0 = LOADBYTES(c, 8);
    uint64_t c1 = LOADBYTES(c + 8, 8);
    STOREBYTES(m, s.x[0] ^ c0, 8);
    STOREBYTES(m + 8, s.x[1] ^ c1, 8);
    s.x[0] = c0;
    s.x[1] = c1;
    P8(&s);
    m += ASCON_128A_RATE;
    c += ASCON_128A_RATE;
    clen -= ASCON_128A_RATE;
  }
  /* final ciphertext block */
  if (clen >= 8) {
    uint64_t c0 = LOADBYTES(c, 8);
    uint64_t c1 = LOADBYTES(c + 8, clen - 8);
    STOREBYTES(m, s.x[0] ^ c0, 8);
    STOREBYTES(m + 8, s.x[1] ^ c1, clen - 8);
    s.x[0] = c0;
    s.x[1] = CLEARBYTES(s.x[1], clen - 8);
    s.x[1] |= c1;
    s.x[1] ^= PAD(clen - 8);
  } else {
    uint64_t c0 = LOADBYTES(c, clen);
    STOREBYTES(m, s.x[0] ^ c0, clen);
    s.x[0] = CLEARBYTES(s.x[0], clen);
    s.x[0] |= c0;
    s.x[0] ^= PAD(clen);
  }
  m += clen;
  c += clen;

  /* finalize */
  s.x[2] ^= K0;
  s.x[3] ^= K1;
  P12(&s);
  s.x[3] ^= K0;
  s.x[4] ^= K1;

  /* get tag */
  uint8_t t[16];
  STOREBYTES(t, s.x[3], 8);
  STOREBYTES(t + 8, s.x[4], 8);

  /* verify should be constant time, check compiler output */
  int i;
  int result = 0;
  for (i = 0; i < CRYPTO_ABYTES; ++i) result |= c[i] ^ t[i];
  result = (((result - 1) >> 8) & 1) - 1;

  return result;
}

#endif

#if defined(ASCON_MACV13) || defined(ASCON_PRFSV13) || defined(ASCON_PRFV13)

int crypto_prf(unsigned char* out, unsigned long long outlen,
               const unsigned char* in, unsigned long long inlen,
               const unsigned char* k) {
  if (CRYPTO_BYTES && outlen > CRYPTO_BYTES) return -1;
  /* load key */
  const uint64_t K0 = LOADBYTES(k, 8);
  const uint64_t K1 = LOADBYTES(k + 8, 8);
  int i;
  /* initialize */
  ascon_state_t s;
  s.x[0] = ASCON_INIT;
  s.x[1] = K0;
  s.x[2] = K1;
  s.x[3] = 0;
  s.x[4] = 0;
  P12(&s);

  /* absorb full plaintext words */
  i = 0;
  while (inlen >= 8) {
    ((uint64_t*)(&s.x[0]))[i] ^= LOADBYTES(in, 8);
    if (++i == 4) i = 0;
    if (i == 0) P12(&s);
    in += 8;
    inlen -= 8;
  }
  /* absorb final plaintext word */
  ((uint64_t*)(&s.x[0]))[i] ^= LOADBYTES(in, inlen);
  ((uint64_t*)(&s.x[0]))[i] ^= PAD(inlen);
  /* domain separation */
  s.x[4] ^= DSEP();

  /* squeeze */
  P12(&s);
  /* squeeze output words */
  i = 0;
  while (outlen > 8) {
    STOREBYTES(out, ((uint64_t*)(&s.x[0]))[i], 8);
    if (++i == 2) i = 0;
    if (i == 0) P12(&s);
    out += 8;
    outlen -= 8;
  }
  /* squeeze final output word */
  STOREBYTES(out, ((uint64_t*)(&s.x[0]))[i], outlen);
  return 0;
}

int crypto_auth(unsigned char* out, const unsigned char* in,
                unsigned long long len, const unsigned char* k) {
  return crypto_prf(out, CRYPTO_BYTES, in, len, k);
}

int crypto_auth_verify(const unsigned char* h, const unsigned char* in,
                       unsigned long long len, const unsigned char* k) {
  int i;
  uint8_t diff = 0;
  uint8_t tag[CRYPTO_BYTES];
  crypto_prf(tag, CRYPTO_BYTES, in, len, k);
  for (i = 0; i < CRYPTO_BYTES; ++i) diff |= h[i] ^ tag[i];
  return (1 & ((diff - 1) >> 8)) - 1;
}

#endif

#ifdef ASCON_CXOF128

int crypto_cxof(unsigned char* out, unsigned long long outlen,
                const unsigned char* in, unsigned long long inlen,
                const unsigned char* cs, unsigned long long cslen) {
  /* initialize */
  ascon_state_t s;
  s.x[0] = ASCON_INIT;
  s.x[1] = 0;
  s.x[2] = 0;
  s.x[3] = 0;
  s.x[4] = 0;
  P12(&s);

  /* absorb customization length */
  s.x[0] ^= cslen * 8;
  P12(&s);

  /* absorb full customization blocks */
  while (cslen >= ASCON_HASH_RATE) {
    s.x[0] ^= LOADBYTES(cs, 8);
    P12(&s);
    cs += ASCON_HASH_RATE;
    cslen -= ASCON_HASH_RATE;
  }
  /* absorb final customization block */
  s.x[0] ^= LOADBYTES(cs, cslen);
  s.x[0] ^= PAD(cslen);
  P12(&s);

  /* absorb full plaintext blocks */
  while (inlen >= ASCON_HASH_RATE) {
    s.x[0] ^= LOADBYTES(in, 8);
    P12(&s);
    in += ASCON_HASH_RATE;
    inlen -= ASCON_HASH_RATE;
  }
  /* absorb final plaintext block */
  s.x[0] ^= LOADBYTES(in, inlen);
  s.x[0] ^= PAD(inlen);
  P12(&s);

  /* squeeze full output blocks */
  while (outlen > ASCON_HASH_RATE) {
    STOREBYTES(out, s.x[0], 8);
    P12(&s);
    out += ASCON_HASH_RATE;
    outlen -= ASCON_HASH_RATE;
  }
  /* squeeze final output block */
  STOREBYTES(out, s.x[0], outlen);

  return 0;
}

int crypto_hash(unsigned char* out, const unsigned char* in,
                unsigned long long len) {
  return crypto_cxof(out, CRYPTO_BYTES, in, len, (void*)0, 0);
}

#endif
