/*
 * Copyright (c) The slhdsa-c project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/* === Ascon eXtensible Output Function (XOF) */

#ifndef _ASCON_API_H_
#define _ASCON_API_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <stddef.h>
#include <stdint.h>
#include "cbmc.h"

  typedef struct { /* state context */
    union {
      uint8_t b[40]; /* 8-bit bytes */
      uint64_t d[5]; /* 64-bit words */
    } st;
    size_t pt, r_sz, md_sz;
  } ascon_var_t;

  /* incremental interfece */
  void asconhash_init(ascon_var_t *c,
                 size_t md_sz) /* md_sz = hash output in bytes */
  __contract__(
    requires(memory_no_alias(c, sizeof(ascon_var_t)))
    requires(md_sz <= 64)
    assigns(object_whole(c))
  );
  void asconxof_init(ascon_var_t *c,
                 size_t md_sz) /* md_sz = hash output in bytes */
  __contract__(
    requires(memory_no_alias(c, sizeof(ascon_var_t)))
    requires(md_sz <= 64)
    assigns(object_whole(c))
  );

  /* absorb input */
  void ascon_absorb(ascon_var_t *c, const void *data, size_t data_sz);
  /* squeeze output */
  void ascon_squeeze(ascon_var_t *c, uint8_t *out, size_t out_sz);

  /* compute a hash "md" of "md_sz" bytes from data in "in" */
  void asconhash(uint8_t *md, size_t md_sz, const void *in, size_t in_sz, size_t r_sz);
  /* compute a hash "md" of "md_sz" bytes from data in "in" */
  void asconxof(uint8_t *md, size_t md_sz, const void *in, size_t in_sz, size_t r_sz);

  /* CONSTANTS_H_ */
#define ASCON_HASH_VARIANT 2
#define ASCON_XOF_VARIANT 3
#define ASCON_PA_ROUNDS 12
#define ASCON_HASH_PB_ROUNDS 12
#define ASCON_HASH_SIZE 32
#define ASCON_HASH_RATE 8
#define ASCON_HASH_IV                         \
  (((uint64_t)(ASCON_HASH_VARIANT) << 0) |    \
   ((uint64_t)(ASCON_PA_ROUNDS) << 16) |      \
   ((uint64_t)(ASCON_HASH_PB_ROUNDS) << 20) | \
   ((uint64_t)(ASCON_HASH_SIZE * 8) << 24) |  \
   ((uint64_t)(ASCON_HASH_RATE) << 40))
#define ASCON_XOF_IV                          \
  (((uint64_t)(ASCON_XOF_VARIANT) << 0) |     \
   ((uint64_t)(ASCON_PA_ROUNDS) << 16) |      \
   ((uint64_t)(ASCON_HASH_PB_ROUNDS) << 20) | \
   ((uint64_t)(ASCON_HASH_RATE) << 40))
  /* CONSTANTS_H_ */

  /* PERMUTATIONS_H_ */
  static inline uint64_t ROR(uint64_t x, int n) {
    return x >> n | x << (-n & 63);
  }
  static inline void ROUND(uint64_t* x, uint8_t C) {
    uint64_t t[5];
    /* addition of round constant */
    x[2] ^= C;
    /* substitution layer */
    x[0] ^= x[4];
    x[4] ^= x[3];
    x[2] ^= x[1];
    /* start of keccak s-box */
    t[0] = x[0] ^ (~x[1] & x[2]);
    t[1] = x[1] ^ (~x[2] & x[3]);
    t[2] = x[2] ^ (~x[3] & x[4]);
    t[3] = x[3] ^ (~x[4] & x[0]);
    t[4] = x[4] ^ (~x[0] & x[1]);
    /* end of keccak s-box */
    t[1] ^= t[0];
    t[0] ^= t[4];
    t[3] ^= t[2];
    t[2] = ~t[2];
    /* linear diffusion layer */
    x[0] = t[0] ^ ROR(t[0], 19) ^ ROR(t[0], 28);
    x[1] = t[1] ^ ROR(t[1], 61) ^ ROR(t[1], 39);
    x[2] = t[2] ^ ROR(t[2], 1) ^ ROR(t[2], 6);
    x[3] = t[3] ^ ROR(t[3], 10) ^ ROR(t[3], 17);
    x[4] = t[4] ^ ROR(t[4], 7) ^ ROR(t[4], 41);
  }
  static inline void P12(uint64_t x[5]) {
    ROUND(x, 0xf0);
    ROUND(x, 0xe1);
    ROUND(x, 0xd2);
    ROUND(x, 0xc3);
    ROUND(x, 0xb4);
    ROUND(x, 0xa5);
    ROUND(x, 0x96);
    ROUND(x, 0x87);
    ROUND(x, 0x78);
    ROUND(x, 0x69);
    ROUND(x, 0x5a);
    ROUND(x, 0x4b);
  }
  /* PERMUTATIONS_H_ */


#ifdef __cplusplus
}
#endif

#endif /* _ASCON_API_H_ */
