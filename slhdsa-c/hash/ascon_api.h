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
  void ascon_init(ascon_var_t *c,
                 size_t md_sz) /* md_sz = hash output in bytes */
  __contract__(
    requires(memory_no_alias(c, sizeof(ascon_var_t)))
    requires(md_sz <= 64)
    assigns(object_whole(c))
  );

  void ascon_update(ascon_var_t *c, const void *data, size_t data_sz);
  void ascon_final(ascon_var_t *c, uint8_t *md); /* digest goes to md */

/* Ascon-XOF128 extensible-output functions */
#define ascon128_init(c) ascon_init(c, 16)
#define ascon256_init(c) ascon_init(c, 32)

  /* compute a hash "md" of "md_sz" bytes from data in "in" */
  void ascon(uint8_t *md, size_t md_sz, const void *in, size_t in_sz, size_t r_sz);
#define ascon128(md, md_sz, in, in_sz) ascon(md, md_sz, in, in_sz, 16)
#define ascon256(md, md_sz, in, in_sz) ascon(md, md_sz, in, in_sz, 32)

  /* squeeze output (can call repeat) */
  void ascon_out(ascon_var_t *c, uint8_t *out, size_t out_sz);
  /* core permutation */
  void ascon_p12(uint64_t x[5]);

#ifdef __cplusplus
}
#endif

#endif /* _ASCON_API_H_ */
