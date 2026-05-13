#ifndef ASCON_H_
#define ASCON_H_

#include <stdint.h>

typedef struct {
  uint64_t x[5];
} ascon_state_t;

#ifdef ASCON_HASH256
#define CRYPTO_VERSION "1.2.8"
#define CRYPTO_BYTES 32
#define ASCON_HASH_BYTES 32 /* HASH */
#define ASCON_HASH_ROUNDS 12
#define ASCON_VARIANT 2
#define ASCON_INIT ASCON_HASH_IV
#endif

#ifdef ASCON_XOF128
#define CRYPTO_VERSION "1.3.0"
#define CRYPTO_BYTES 64
#define ASCON_HASH_BYTES 0 /* XOF */
#define ASCON_HASH_ROUNDS 12
#define ASCON_VARIANT 3
#define ASCON_INIT ASCON_XOF_IV
#endif

#ifdef ASCON_AEAD128
#define CRYPTO_VERSION "1.3.0"
#define CRYPTO_KEYBYTES 16
#define CRYPTO_NSECBYTES 0
#define CRYPTO_NPUBBYTES 16
#define CRYPTO_ABYTES 16
#define CRYPTO_NOOVERLAP 1
#define ASCON_AEAD_RATE 16
#define ASCON_VARIANT 1
#define ASCON_INIT ASCON_128A_IV
#endif

#ifdef ASCON_AEADXOF128
#define CRYPTO_VERSION "1.3.0"
// AEAD defines
#define CRYPTO_KEYBYTES 16
#define CRYPTO_NSECBYTES 0
#define CRYPTO_NPUBBYTES 16
#define CRYPTO_ABYTES 16
#define CRYPTO_NOOVERLAP 1
#define ASCON_AEAD_RATE 16
// Hash defines
#define CRYPTO_BYTES 64
#define ASCON_HASH_BYTES 0 /* XOF */
#define ASCON_HASH_ROUNDS 12
#define ASCON_VARIANT 3
// Hash init
#define ASCON_INIT ASCON_XOF_IV
#endif

#ifdef ASCON_MACV13
#define CRYPTO_VERSION "1.3.0"
#define CRYPTO_KEYBYTES 16
#define CRYPTO_BYTES 16
#define CRYPTO_NOOVERLAP 1
#define ASCON_PRF_BYTES 16
#define ASCON_PRF_ROUNDS 12
#define ASCON_VARIANT 5
#define ASCON_INIT ASCON_MAC_IV
#endif

#ifdef ASCON_PRFSV13
#define CRYPTO_VERSION "1.3.0"
#define CRYPTO_KEYBYTES 16
#define CRYPTO_BYTES 16
#define CRYPTO_NOOVERLAP 1
#define ASCON_PRF_BYTES 16
#define ASCON_VARIANT 7
#define ASCON_INIT ASCON_PRFS_IV | (uint64_t)(inlen * 8) << 48
#endif

#ifdef ASCON_PRFV13
#define CRYPTO_VERSION "1.3.0"
#define CRYPTO_KEYBYTES 16
#define CRYPTO_BYTES 64
#define CRYPTO_NOOVERLAP 1
#define ASCON_PRF_BYTES 0
#define ASCON_PRF_ROUNDS 12
#define ASCON_VARIANT 6
#define ASCON_INIT ASCON_PRF_IV
#endif

#ifdef ASCON_CXOF128
#define CRYPTO_VERSION "1.3.0"
#define CRYPTO_BYTES 64
#define ASCON_HASH_BYTES 0 /* XOF */
#define ASCON_HASH_ROUNDS 12
#define ASCON_VARIANT 4
#define ASCON_INIT ASCON_CXOF_IV
#endif



/* CONSTANTS_H_ */

#define ASCON_80PQ_VARIANT 0
#define ASCON_AEAD_VARIANT 1
#define ASCON_HASH_VARIANT 2
#define ASCON_XOF_VARIANT 3
#define ASCON_CXOF_VARIANT 4
#define ASCON_MAC_VARIANT 5
#define ASCON_PRF_VARIANT 6
#define ASCON_PRFS_VARIANT 7

#define ASCON_TAG_SIZE 16
#define ASCON_HASH_SIZE 32

#define ASCON_128_RATE 8
#define ASCON_128A_RATE 16
#define ASCON_HASH_RATE 8
#define ASCON_PRF_IN_RATE 32
#define ASCON_PRFA_IN_RATE 40
#define ASCON_PRF_OUT_RATE 16

#define ASCON_PA_ROUNDS 12
#define ASCON_128_PB_ROUNDS 6
#define ASCON_128A_PB_ROUNDS 8
#define ASCON_HASH_PB_ROUNDS 12
#define ASCON_HASHA_PB_ROUNDS 8
#define ASCON_PRF_PB_ROUNDS 12
#define ASCON_PRFA_PB_ROUNDS 8

#define ASCON_128_IV                         \
  (((uint64_t)(ASCON_AEAD_VARIANT) << 0) |   \
   ((uint64_t)(ASCON_PA_ROUNDS) << 16) |     \
   ((uint64_t)(ASCON_128_PB_ROUNDS) << 20) | \
   ((uint64_t)(ASCON_TAG_SIZE * 8) << 24) |  \
   ((uint64_t)(ASCON_128_RATE) << 40))

#define ASCON_128A_IV                         \
  (((uint64_t)(ASCON_AEAD_VARIANT) << 0) |    \
   ((uint64_t)(ASCON_PA_ROUNDS) << 16) |      \
   ((uint64_t)(ASCON_128A_PB_ROUNDS) << 20) | \
   ((uint64_t)(ASCON_TAG_SIZE * 8) << 24) |   \
   ((uint64_t)(ASCON_128A_RATE) << 40))

#define ASCON_80PQ_IV                                                          \
  (((uint64_t)(ASCON_80PQ_VARIANT) << 0) | ((uint64_t)(ASCON_128_RATE) << 8) | \
   ((uint64_t)(ASCON_PA_ROUNDS) << 16) |                                       \
   ((uint64_t)(ASCON_128_PB_ROUNDS) << 20) |                                   \
   ((uint64_t)(ASCON_TAG_SIZE * 8) << 24))

#define ASCON_HASH_IV                         \
  (((uint64_t)(ASCON_HASH_VARIANT) << 0) |    \
   ((uint64_t)(ASCON_PA_ROUNDS) << 16) |      \
   ((uint64_t)(ASCON_HASH_PB_ROUNDS) << 20) | \
   ((uint64_t)(ASCON_HASH_SIZE * 8) << 24) |  \
   ((uint64_t)(ASCON_HASH_RATE) << 40))

#define ASCON_HASHA_IV                         \
  (((uint64_t)(ASCON_HASH_VARIANT) << 0) |     \
   ((uint64_t)(ASCON_PA_ROUNDS) << 16) |       \
   ((uint64_t)(ASCON_HASHA_PB_ROUNDS) << 20) | \
   ((uint64_t)(ASCON_HASH_SIZE * 8) << 24) |   \
   ((uint64_t)(ASCON_HASH_RATE) << 40))

#define ASCON_XOF_IV                          \
  (((uint64_t)(ASCON_XOF_VARIANT) << 0) |     \
   ((uint64_t)(ASCON_PA_ROUNDS) << 16) |      \
   ((uint64_t)(ASCON_HASH_PB_ROUNDS) << 20) | \
   ((uint64_t)(ASCON_HASH_RATE) << 40))

#define ASCON_XOFA_IV                          \
  (((uint64_t)(ASCON_XOF_VARIANT) << 0) |      \
   ((uint64_t)(ASCON_PA_ROUNDS) << 16) |       \
   ((uint64_t)(ASCON_HASHA_PB_ROUNDS) << 20) | \
   ((uint64_t)(ASCON_HASH_RATE) << 40))

#define ASCON_CXOF_IV                         \
  (((uint64_t)(ASCON_CXOF_VARIANT) << 0) |    \
   ((uint64_t)(ASCON_PA_ROUNDS) << 16) |      \
   ((uint64_t)(ASCON_HASH_PB_ROUNDS) << 20) | \
   ((uint64_t)(ASCON_HASH_RATE) << 40))

#define ASCON_CXOFA_IV                         \
  (((uint64_t)(ASCON_CXOF_VARIANT) << 0) |     \
   ((uint64_t)(ASCON_PA_ROUNDS) << 16) |       \
   ((uint64_t)(ASCON_HASHA_PB_ROUNDS) << 20) | \
   ((uint64_t)(ASCON_HASH_RATE) << 40))

#define ASCON_MAC_IV                         \
  (((uint64_t)(ASCON_MAC_VARIANT) << 0) |    \
   ((uint64_t)(ASCON_PA_ROUNDS) << 16) |     \
   ((uint64_t)(ASCON_PRF_PB_ROUNDS) << 20) | \
   ((uint64_t)(ASCON_TAG_SIZE * 8) << 24) |  \
   ((uint64_t)(ASCON_PRF_IN_RATE) << 40) |   \
   ((uint64_t)(ASCON_PRF_OUT_RATE) << 48))

#define ASCON_MACA_IV                         \
  (((uint64_t)(ASCON_MAC_VARIANT) << 0) |     \
   ((uint64_t)(ASCON_PA_ROUNDS) << 16) |      \
   ((uint64_t)(ASCON_PRFA_PB_ROUNDS) << 20) | \
   ((uint64_t)(ASCON_TAG_SIZE * 8) << 24) |   \
   ((uint64_t)(ASCON_PRFA_IN_RATE) << 40) |   \
   ((uint64_t)(ASCON_PRF_OUT_RATE) << 48))

#define ASCON_PRF_IV                         \
  (((uint64_t)(ASCON_PRF_VARIANT) << 0) |    \
   ((uint64_t)(ASCON_PA_ROUNDS) << 16) |     \
   ((uint64_t)(ASCON_PRF_PB_ROUNDS) << 20) | \
   ((uint64_t)(ASCON_PRF_IN_RATE) << 40) |   \
   ((uint64_t)(ASCON_PRF_OUT_RATE) << 48))

#define ASCON_PRFA_IV                         \
  (((uint64_t)(ASCON_PRF_VARIANT) << 0) |     \
   ((uint64_t)(ASCON_PA_ROUNDS) << 16) |      \
   ((uint64_t)(ASCON_PRFA_PB_ROUNDS) << 20) | \
   ((uint64_t)(ASCON_PRFA_IN_RATE) << 40) |   \
   ((uint64_t)(ASCON_PRF_OUT_RATE) << 48))

#define ASCON_PRFS_IV                      \
  (((uint64_t)(ASCON_PRFS_VARIANT) << 0) | \
   ((uint64_t)(ASCON_PA_ROUNDS) << 16) |   \
   ((uint64_t)(ASCON_TAG_SIZE * 8) << 24))

/* CONSTANTS_H_ */



/* ROUND_H_ */

static inline uint64_t ROR(uint64_t x, int n) {
  return x >> n | x << (-n & 63);
}

static inline void ROUND(ascon_state_t* s, uint8_t C) {
  ascon_state_t t;
  /* addition of round constant */
  s->x[2] ^= C;
  /* substitution layer */
  s->x[0] ^= s->x[4];
  s->x[4] ^= s->x[3];
  s->x[2] ^= s->x[1];
  /* start of keccak s-box */
  t.x[0] = s->x[0] ^ (~s->x[1] & s->x[2]);
  t.x[1] = s->x[1] ^ (~s->x[2] & s->x[3]);
  t.x[2] = s->x[2] ^ (~s->x[3] & s->x[4]);
  t.x[3] = s->x[3] ^ (~s->x[4] & s->x[0]);
  t.x[4] = s->x[4] ^ (~s->x[0] & s->x[1]);
  /* end of keccak s-box */
  t.x[1] ^= t.x[0];
  t.x[0] ^= t.x[4];
  t.x[3] ^= t.x[2];
  t.x[2] = ~t.x[2];
  /* linear diffusion layer */
  s->x[0] = t.x[0] ^ ROR(t.x[0], 19) ^ ROR(t.x[0], 28);
  s->x[1] = t.x[1] ^ ROR(t.x[1], 61) ^ ROR(t.x[1], 39);
  s->x[2] = t.x[2] ^ ROR(t.x[2], 1) ^ ROR(t.x[2], 6);
  s->x[3] = t.x[3] ^ ROR(t.x[3], 10) ^ ROR(t.x[3], 17);
  s->x[4] = t.x[4] ^ ROR(t.x[4], 7) ^ ROR(t.x[4], 41);
}

/* ROUND_H_ */



/* PERMUTATIONS_H_ */

static inline void P12(ascon_state_t* s) {
  ROUND(s, 0xf0);
  ROUND(s, 0xe1);
  ROUND(s, 0xd2);
  ROUND(s, 0xc3);
  ROUND(s, 0xb4);
  ROUND(s, 0xa5);
  ROUND(s, 0x96);
  ROUND(s, 0x87);
  ROUND(s, 0x78);
  ROUND(s, 0x69);
  ROUND(s, 0x5a);
  ROUND(s, 0x4b);
}

static inline void P8(ascon_state_t* s) {
  ROUND(s, 0xb4);
  ROUND(s, 0xa5);
  ROUND(s, 0x96);
  ROUND(s, 0x87);
  ROUND(s, 0x78);
  ROUND(s, 0x69);
  ROUND(s, 0x5a);
  ROUND(s, 0x4b);
}

static inline void P6(ascon_state_t* s) {
  ROUND(s, 0x96);
  ROUND(s, 0x87);
  ROUND(s, 0x78);
  ROUND(s, 0x69);
  ROUND(s, 0x5a);
  ROUND(s, 0x4b);
}

/* PERMUTATIONS_H_ */



/* WORD_H_ */

/* get byte from 64-bit Ascon word */
#define GETBYTE(x, i) ((uint8_t)((uint64_t)(x) >> (8 * (i))))

/* set byte in 64-bit Ascon word */
#define SETBYTE(b, i) ((uint64_t)(b) << (8 * (i)))

/* set padding byte in 64-bit Ascon word */
#define PAD(i) SETBYTE(0x01, i)

/* define domain separation bit in 64-bit Ascon word */
#define DSEP() SETBYTE(0x80, 7)

/* load bytes into 64-bit Ascon word */
static inline uint64_t LOADBYTES(const uint8_t* bytes, int n) {
  int i;
  uint64_t x = 0;
  for (i = 0; i < n; ++i) x |= SETBYTE(bytes[i], i);
  return x;
}

/* store bytes from 64-bit Ascon word */
static inline void STOREBYTES(uint8_t* bytes, uint64_t x, int n) {
  int i;
  for (i = 0; i < n; ++i) bytes[i] = GETBYTE(x, i);
}

/* clear bytes in 64-bit Ascon word */
static inline uint64_t CLEARBYTES(uint64_t x, int n) {
  int i;
  for (i = 0; i < n; ++i) x &= ~SETBYTE(0xff, i);
  return x;
}

/* WORD_H_ */


#endif /* ASCON_H_ */
