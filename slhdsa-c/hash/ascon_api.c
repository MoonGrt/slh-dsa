/*
 * Copyright (c) The slhdsa-c project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/* === Ascon-XOF128 incremental interface */

#include <string.h>
#include "ascon_api.h"
#include "cbmc.h"

/* initialize the context for SHA3 */

static uint64_t ascon_byte(uint8_t x, size_t i) {
  return (uint64_t)x << (8 * i);
}

void asconhash_init(ascon_var_t *c, size_t md_sz) {
  memset(c, 0, sizeof(ascon_var_t));
  c->st.d[0] = ASCON_HASH_IV;
  c->r_sz = ASCON_HASH_RATE;
  c->md_sz = md_sz;
  c->pt = 0;
  P12(c->st.d);
}

void asconxof_init(ascon_var_t *c, size_t md_sz) {
  memset(c, 0, sizeof(ascon_var_t));
  c->st.d[0] = ASCON_XOF_IV;
  c->r_sz = ASCON_HASH_RATE;
  c->md_sz = md_sz;
  c->pt = 0;
  P12(c->st.d);
}

/* update state with more data */

/* absorb input */
void ascon_absorb(ascon_var_t *c, const void *data, size_t len) {
  const uint8_t *in = (const uint8_t *)data;
  size_t i, j;
  j = c->pt;
  for (i = 0; i < len; i++) {
    c->st.d[0] ^= ascon_byte(in[i], j++);
    if (j >= c->r_sz) {
      P12(c->st.d);
      j = 0;
    }
  }
  c->pt = j;
}

/* squeeze output */
void ascon_squeeze(ascon_var_t *c, uint8_t *out, size_t out_sz) {
  size_t i, j;
  /* add padding on the first call */
  if (c->md_sz != 0) {
    c->st.d[0] ^= ascon_byte(0x01, c->pt);
    P12(c->st.d);
    c->pt = 0;
    c->md_sz = 0;
  }
  j = c->pt;
  for (i = 0; i < out_sz; i++) {
    if (j >= c->r_sz) {
      P12(c->st.d);
      j = 0;
    }
    out[i] = (uint8_t)(c->st.d[0] >> (8 * (j++)));
  }
  c->pt = j;
}

/* compute a ASCON hash "md" of "md_sz" bytes from data in "in" */

void asconhash(uint8_t *md, size_t md_sz, const void *in, size_t in_sz, size_t r_sz) {
  ascon_var_t ascon;
  asconhash_init(&ascon, r_sz);
  ascon_absorb(&ascon, in, in_sz);
  ascon_squeeze(&ascon, md, md_sz);
}

/* compute a ASCON hash "md" of "md_sz" bytes from data in "in" */

void asconxof(uint8_t *md, size_t md_sz, const void *in, size_t in_sz, size_t r_sz) {
  ascon_var_t ascon;
  asconxof_init(&ascon, r_sz);
  ascon_absorb(&ascon, in, in_sz);
  ascon_squeeze(&ascon, md, md_sz);
}
