/*
 * Copyright (c) The slhdsa-c project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/* === FIPS 202: SHA-3 hash and SHAKE eXtensible Output Functions (XOF) */

#include <string.h>
#include "sha3_api.h"
#include "cbmc.h"

/* These functions have not been optimized for performance. */
/* initialize the context for SHA3 */

void sha3_init(sha3_var_t *c, size_t md_sz) {
  memset(c->st.d, 0, 25*sizeof(uint64_t));
  c->md_sz = md_sz; /* in SHAKE; if 0, padding done */
  c->r_sz = 200 - 2 * md_sz;
  c->pt = 0;
}

/* update state with more data */

void sha3_update(sha3_var_t *c, const void *data, size_t len) {
  size_t i, j;
  j = c->pt;
  for (i = 0; i < len; i++) {
    c->st.b[j++] ^= ((const uint8_t *)data)[i];
    if (j >= c->r_sz) {
      keccak_f1600(c->st.d);
      j = 0;
    }
  }
  c->pt = j;
}

/* finalize and output a hash */

void sha3_final(sha3_var_t *c, uint8_t *md) {
  size_t i;
  c->st.b[c->pt] ^= 0x06;
  c->st.b[c->r_sz - 1] ^= 0x80;
  keccak_f1600(c->st.d);
  for (i = 0; i < c->md_sz; i++)
    md[i] = c->st.b[i];
}

/* compute a SHA-3 hash "md" of "md_sz" bytes from data in "in" */

void sha3(uint8_t *md, size_t md_sz, const void *in, size_t in_sz) {
  sha3_var_t sha3;
  sha3_init(&sha3, md_sz);
  sha3_update(&sha3, in, in_sz);
  sha3_final(&sha3, md);
}

/* SHAKE128 and SHAKE256 extensible-output functionality */
/* squeeze output */

void shake_out(sha3_var_t *c, uint8_t *out, size_t out_sz) {
  size_t i, j;
  /* add padding on the first call */
  if (c->md_sz != 0) {
    c->st.b[c->pt] ^= 0x1F;
    c->st.b[c->r_sz - 1] ^= 0x80;
    keccak_f1600(c->st.d);
    c->pt = 0;
    c->md_sz = 0;
  }
  j = c->pt;
  for (i = 0; i < out_sz; i++) {
    if (j >= c->r_sz) {
      keccak_f1600(c->st.d);
      j = 0;
    }
    out[i] = c->st.b[j++];
  }
  c->pt = j;
}

/* compute a SHAKE hash "md" of "md_sz" bytes from data in "in" */

void shake(uint8_t *md, size_t md_sz, const void *in, size_t in_sz, size_t r_sz) {
  sha3_var_t sha3;
  sha3_init(&sha3, r_sz);
  sha3_update(&sha3, in, in_sz);
  shake_out(&sha3, md, md_sz);
}


#include "plat_local.h"

#ifdef SLH_EXPERIMENTAL
uint64_t keccak_f1600_count = 0; /* instrumentation */
#endif

/* forward permutation */

void keccak_f1600(uint64_t x[25]) {
  /* round constants */
  static const uint64_t keccak_rc[24] = {
      UINT64_C(0x0000000000000001), UINT64_C(0x0000000000008082),
      UINT64_C(0x800000000000808A), UINT64_C(0x8000000080008000),
      UINT64_C(0x000000000000808B), UINT64_C(0x0000000080000001),
      UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008009),
      UINT64_C(0x000000000000008A), UINT64_C(0x0000000000000088),
      UINT64_C(0x0000000080008009), UINT64_C(0x000000008000000A),
      UINT64_C(0x000000008000808B), UINT64_C(0x800000000000008B),
      UINT64_C(0x8000000000008089), UINT64_C(0x8000000000008003),
      UINT64_C(0x8000000000008002), UINT64_C(0x8000000000000080),
      UINT64_C(0x000000000000800A), UINT64_C(0x800000008000000A),
      UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008080),
      UINT64_C(0x0000000080000001), UINT64_C(0x8000000080008008)};

  int i;
  uint64_t t, y0, y1, y2, y3, y4;

#ifdef SLH_EXPERIMENTAL
  keccak_f1600_count++; /* instrumentation */
#endif

  /* iteration */

  for (i = 0; i < 24; i++) {
    /* Theta */

    y4 = x[4] ^ x[9] ^ x[14] ^ x[19] ^ x[24];
    y1 = x[1] ^ x[6] ^ x[11] ^ x[16] ^ x[21];
    y3 = x[3] ^ x[8] ^ x[13] ^ x[18] ^ x[23];
    y0 = x[0] ^ x[5] ^ x[10] ^ x[15] ^ x[20];
    y2 = x[2] ^ x[7] ^ x[12] ^ x[17] ^ x[22];

    t = ror64(y4, 63);
    y4 ^= ror64(y1, 63);
    y1 ^= ror64(y3, 63);
    y3 ^= ror64(y0, 63);
    y0 ^= ror64(y2, 63);
    y2 ^= t;

    x[0] ^= y4;
    x[1] ^= y0;
    x[2] ^= y1;
    x[3] ^= y2;
    x[4] ^= y3;
    x[5] ^= y4;
    x[6] ^= y0;
    x[7] ^= y1;
    x[8] ^= y2;
    x[9] ^= y3;
    x[10] ^= y4;
    x[11] ^= y0;
    x[12] ^= y1;
    x[13] ^= y2;
    x[14] ^= y3;
    x[15] ^= y4;
    x[16] ^= y0;
    x[17] ^= y1;
    x[18] ^= y2;
    x[19] ^= y3;
    x[20] ^= y4;
    x[21] ^= y0;
    x[22] ^= y1;
    x[23] ^= y2;
    x[24] ^= y3;

    /* Rho Pi */

    t = ror64(x[1], 63);
    x[1] = ror64(x[6], 20);
    x[6] = ror64(x[9], 44);
    x[9] = ror64(x[22], 3);
    x[22] = ror64(x[14], 25);
    x[14] = ror64(x[20], 46);
    x[20] = ror64(x[2], 2);
    x[2] = ror64(x[12], 21);
    x[12] = ror64(x[13], 39);
    x[13] = ror64(x[19], 56);
    x[19] = ror64(x[23], 8);
    x[23] = ror64(x[15], 23);
    x[15] = ror64(x[4], 37);
    x[4] = ror64(x[24], 50);
    x[24] = ror64(x[21], 62);
    x[21] = ror64(x[8], 9);
    x[8] = ror64(x[16], 19);
    x[16] = ror64(x[5], 28);
    x[5] = ror64(x[3], 36);
    x[3] = ror64(x[18], 43);
    x[18] = ror64(x[17], 49);
    x[17] = ror64(x[11], 54);
    x[11] = ror64(x[7], 58);
    x[7] = ror64(x[10], 61);
    x[10] = t;

    /* Chi */

    t = x[4] & ~x[3];
    x[4] ^= x[1] & ~x[0];
    x[1] ^= x[3] & ~x[2];
    x[3] ^= x[0] & ~x[4];
    x[0] ^= x[2] & ~x[1];
    x[2] ^= t;

    t = x[9] & ~x[8];
    x[9] ^= x[6] & ~x[5];
    x[6] ^= x[8] & ~x[7];
    x[8] ^= x[5] & ~x[9];
    x[5] ^= x[7] & ~x[6];
    x[7] ^= t;

    t = x[14] & ~x[13];
    x[14] ^= x[11] & ~x[10];
    x[11] ^= x[13] & ~x[12];
    x[13] ^= x[10] & ~x[14];
    x[10] ^= x[12] & ~x[11];
    x[12] ^= t;

    t = x[19] & ~x[18];
    x[19] ^= x[16] & ~x[15];
    x[16] ^= x[18] & ~x[17];
    x[18] ^= x[15] & ~x[19];
    x[15] ^= x[17] & ~x[16];
    x[17] ^= t;

    t = x[24] & ~x[23];
    x[24] ^= x[21] & ~x[20];
    x[21] ^= x[23] & ~x[22];
    x[23] ^= x[20] & ~x[24];
    x[20] ^= x[22] & ~x[21];
    x[22] ^= t;

    /* Iota */

    x[0] = x[0] ^ keccak_rc[i];
  }
}
