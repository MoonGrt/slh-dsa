/*
 * Copyright (c) The slhdsa-c project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/* === Ascon-XOF128 incremental interface */

#include <string.h>
#include "ascon_api.h"
#include "cbmc.h"

/* initialize the context for SHA3 */

#include "plat_local.h"

static uint64_t ascon_byte(uint8_t x, size_t i) {
  return (uint64_t)x << (8 * i);
}

void ascon_p12(uint64_t x[5]) {
  static const uint8_t rc[12] = {0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5,
                                 0x96, 0x87, 0x78, 0x69, 0x5A, 0x4B};
  uint64_t t[5];
  size_t i;

  for (i = 0; i < 12; i++) {
    x[2] ^= rc[i];

    x[0] ^= x[4];
    x[4] ^= x[3];
    x[2] ^= x[1];

    t[0] = x[0] ^ (~x[1] & x[2]);
    t[1] = x[1] ^ (~x[2] & x[3]);
    t[2] = x[2] ^ (~x[3] & x[4]);
    t[3] = x[3] ^ (~x[4] & x[0]);
    t[4] = x[4] ^ (~x[0] & x[1]);

    t[1] ^= t[0];
    t[0] ^= t[4];
    t[3] ^= t[2];
    t[2] = ~t[2];

    x[0] = t[0] ^ ror64(t[0], 19) ^ ror64(t[0], 28);
    x[1] = t[1] ^ ror64(t[1], 61) ^ ror64(t[1], 39);
    x[2] = t[2] ^ ror64(t[2], 1) ^ ror64(t[2], 6);
    x[3] = t[3] ^ ror64(t[3], 10) ^ ror64(t[3], 17);
    x[4] = t[4] ^ ror64(t[4], 7) ^ ror64(t[4], 41);
  }
}

void ascon_init(ascon_var_t *c, size_t md_sz) {
  memset(c, 0, sizeof(ascon_var_t));
  c->st.d[0] = ASCON_XOF_IV;
  c->r_sz = ASCON_XOF_RATE;
  c->md_sz = md_sz;
  c->pt = 0;
  ascon_p12(c->st.d);
}

/* update state with more data */

void ascon_update(ascon_var_t *c, const void *data, size_t len) {
  const uint8_t *in = (const uint8_t *)data;
  size_t i;
  for (i = 0; i < len; i++) {
    c->st.d[0] ^= ascon_byte(in[i], c->pt);
    c->pt++;
    if (c->pt == c->r_sz) {
      ascon_p12(c->st.d);
      c->pt = 0;
    }
  }
}

/* finalize and output a hash */

void ascon_final(ascon_var_t *c, uint8_t *md) {
  ascon_out(c, md, c->md_sz);
}

/* compute a ASCON hash "md" of "md_sz" bytes from data in "in" */

/* ASCON XOF extensible-output functionality */
/* squeeze output */

void ascon_out(ascon_var_t *c, uint8_t *out, size_t out_sz) {
  size_t i;
  if (c->md_sz != 0) {
    c->st.d[0] ^= ascon_byte(0x01, c->pt);
    ascon_p12(c->st.d);
    c->pt = 0;
    c->md_sz = 0;
  }
  for (i = 0; i < out_sz; i++) {
    if (c->pt == c->r_sz) {
      ascon_p12(c->st.d);
      c->pt = 0;
    }
    out[i] = (uint8_t)(c->st.d[0] >> (8 * c->pt));
    c->pt++;
  }
}

/* compute a ASCON hash "md" of "md_sz" bytes from data in "in" */

void ascon(uint8_t *md, size_t md_sz, const void *in, size_t in_sz, size_t r_sz) {
  ascon_var_t ascon;
  (void)r_sz;
  ascon_init(&ascon, md_sz);
  ascon_update(&ascon, in, in_sz);
  ascon_out(&ascon, md, md_sz);
}
