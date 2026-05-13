/*
 * Copyright (c) The slhdsa-c project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/* === Portable C code: Functions for instantiation of SLH-DSA with ASCON */

#include <string.h>
#include "ascon_api.h"
#include "slh_adrs.h"
#include "slh_var.h"

/* === 10.1.   SLH-DSA Using ASCON */

/* Hmsg(R, PK.seed, PK.root, M) = ASCON256(R || PK.seed || PK.root || M, */
/* 8m) */

static void ascon_h_msg(slh_var_t *var, uint8_t *h, const uint8_t *r,
                        const uint8_t *m, size_t m_sz, const uint8_t *ctx,
                        size_t ctx_sz) {
  ascon_var_t ascon;
  size_t n = var->prm->n;
  uint8_t buf[2];

  asconxof256_init(&ascon);
  ascon_update(&ascon, r, n);
  ascon_update(&ascon, var->pk_seed, n);
  ascon_update(&ascon, var->pk_root, n);

  /* add "pure" domain separator and context, if supplied */
  if (ctx_sz != SLH_CTX_SZ_NO_CONTEXT) {
    buf[0] = 0;
    buf[1] = ctx_sz & 0xFF;
    ascon_update(&ascon, buf, 2);
    ascon_update(&ascon, ctx, ctx_sz);
  }
  ascon_update(&ascon, m, m_sz);
  asconxof_out(&ascon, h, var->prm->m);
}

/* F(PK.seed, ADRS, M1 ) = ASCON256(PK.seed || ADRS || M1, 8n) */

static void ascon_f(slh_var_t *var, uint8_t *h, const uint8_t *m1) {
  ascon_var_t ascon;
  size_t n = var->prm->n;
  asconxof256_init(&ascon);
  ascon_update(&ascon, var->pk_seed, n);
  ascon_update(&ascon, (const uint8_t *)var->adrs->u8, 32);
  ascon_update(&ascon, m1, n);
  asconxof_out(&ascon, h, n);
}

/* PRF(PK.seed, SK.seed, ADRS) = ASCON256(PK.seed || ADRS || SK.seed, 8n) */

static void ascon_prf(slh_var_t *var, uint8_t *h) {
  ascon_f(var, h, var->sk_seed);
}

/* PRFmsg (SK.prf, opt_rand, M) = ASCON256(SK.prf || opt_rand || M, 8n) */

static void ascon_prf_msg(slh_var_t *var, uint8_t *h, const uint8_t *opt_rand,
                          const uint8_t *m, size_t m_sz, const uint8_t *ctx,
                          size_t ctx_sz) {
  ascon_var_t ascon;
  size_t n = var->prm->n;
  uint8_t buf[2];

  asconxof256_init(&ascon);
  ascon_update(&ascon, var->sk_prf, n);
  ascon_update(&ascon, opt_rand, n);

  /* add "pure" domain separator and context, if supplied */
  if (ctx_sz != SLH_CTX_SZ_NO_CONTEXT) {
    buf[0] = 0;
    buf[1] = ctx_sz & 0xFF;
    ascon_update(&ascon, buf, 2);
    ascon_update(&ascon, ctx, ctx_sz);
  }
  ascon_update(&ascon, m, m_sz);
  asconxof_out(&ascon, h, n);
}

/* T_l(PK.seed, ADRS, M ) = ASCON256(PK.seed || ADRS || Ml, 8n) */

static void ascon_t(slh_var_t *var, uint8_t *h, const uint8_t *m, size_t m_sz) {
  ascon_var_t ascon;
  size_t n = var->prm->n;
  asconxof256_init(&ascon);
  ascon_update(&ascon, var->pk_seed, n);
  ascon_update(&ascon, (const uint8_t *)var->adrs->u8, 32);
  ascon_update(&ascon, m, m_sz);
  asconxof_out(&ascon, h, n);
}

/* H(PK.seed, ADRS, M2 ) = ASCON256(PK.seed || ADRS || M2, 8n) */

static void ascon_h(slh_var_t *var, uint8_t *h, const uint8_t *m1,
                    const uint8_t *m2) {
  ascon_var_t ascon;
  size_t n = var->prm->n;
  asconxof256_init(&ascon);
  ascon_update(&ascon, var->pk_seed, n);
  ascon_update(&ascon, (const uint8_t *)var->adrs->u8, 32);
  ascon_update(&ascon, m1, n);
  ascon_update(&ascon, m2, n);
  asconxof_out(&ascon, h, n);
}

/* create a context */

static void ascon_mk_var(slh_var_t *var, const uint8_t *pk, const uint8_t *sk,
                         const slh_param_t *prm) {
  size_t n = prm->n;

  var->prm = prm; /* store fixed parameters */
  if (sk != NULL) {
    memcpy(var->sk_seed, sk, n);
    memcpy(var->sk_prf, sk + n, n);
    memcpy(var->pk_seed, sk + 2 * n, n);
    memcpy(var->pk_root, sk + 3 * n, n);
  }
  else if (pk != NULL) {
    memcpy(var->pk_seed, pk, n);
    memcpy(var->pk_root, pk + n, n);
  }

  /* local ADRS buffer */
  var->adrs = &var->t_adrs;
}

/* === Chaining function used in WOTS+ */
/* Algorithm 5: chain(X, i, s, PK.seed, ADRS) */

static void ascon_chain(slh_var_t *var, uint8_t *tmp, const uint8_t *x,
                        uint32_t i, uint32_t s) {
  uint32_t j;

  if (s == 0) { /* no-op */
    memcpy(tmp, x, var->prm->n);
    return;
  }

  memcpy(tmp, x, var->prm->n);
  for (j = 0; j < s; j++) {
    adrs_set_hash_address(var, i + j); /* address */
    ascon_f(var, tmp, tmp);
  }
}

/* Combination WOTS PRF + Chain */

static void ascon_wots_chain(slh_var_t *var, uint8_t *tmp, uint32_t s) {
  /* PRF secret key */
  adrs_set_type(var, ADRS_WOTS_PRF);
  adrs_set_tree_index(var, 0);
  ascon_prf(var, tmp);
  /* chain */
  adrs_set_type(var, ADRS_WOTS_HASH);
  ascon_chain(var, tmp, tmp, 0, s);
}

/* Combination FORS PRF + F (if s == 1) */

static void ascon_fors_hash(slh_var_t *var, uint8_t *tmp, uint32_t s) {
  /* PRF secret key */
  adrs_set_type(var, ADRS_FORS_PRF);
  adrs_set_tree_height(var, 0);
  ascon_prf(var, tmp);
  /* hash it again */
  if (s == 1) {
    adrs_set_type(var, ADRS_FORS_TREE);
    ascon_f(var, tmp, tmp);
  }
}

/* parameter sets */

const slh_param_t slh_dsa_ascon_128s = {
  /* .alg_id = */ "SLH-DSA-ASCON-128s",
  /* .n = */ 16,
  /* .h = */ 63,
  /* .d = */ 7,
  /* .hp = */ 9,
  /* .a = */ 12,
  /* .k = */ 14,
  /* .lg_w = */ 4,
  /* .m = */ 30,
  /* .mk_var = */ ascon_mk_var,
  /* .chain = */ ascon_chain,
  /* .wots_chain = */ ascon_wots_chain,
  /* .fors_hash = */ ascon_fors_hash,
  /* .h_msg = */ ascon_h_msg,
  /* .prf = */ ascon_prf,
  /* .prf_msg = */ ascon_prf_msg,
  /* .h_f = */ ascon_f,
  /* .h_h = */ ascon_h,
  /* .h_t = */ ascon_t
};

const slh_param_t slh_dsa_ascon_128f = {
  /* .alg_id = */ "SLH-DSA-ASCON-128f",
  /* .n = */ 16,
  /* .h = */ 66,
  /* .d = */ 22,
  /* .hp = */ 3,
  /* .a = */ 6,
  /* .k = */ 33,
  /* .lg_w = */ 4,
  /* .m = */ 34,
  /* .mk_var = */ ascon_mk_var,
  /* .chain = */ ascon_chain,
  /* .wots_chain = */ ascon_wots_chain,
  /* .fors_hash = */ ascon_fors_hash,
  /* .h_msg = */ ascon_h_msg,
  /* .prf = */ ascon_prf,
  /* .prf_msg = */ ascon_prf_msg,
  /* .h_f = */ ascon_f,
  /* .h_h = */ ascon_h,
  /* .h_t = */ ascon_t
};

const slh_param_t slh_dsa_ascon_192s = {
  /* .alg_id = */ "SLH-DSA-ASCON-192s",
  /* .n = */ 24,
  /* .h = */ 63,
  /* .d = */ 7,
  /* .hp = */ 9,
  /* .a = */ 14,
  /* .k = */ 17,
  /* .lg_w = */ 4,
  /* .m = */ 39,
  /* .mk_var = */ ascon_mk_var,
  /* .chain = */ ascon_chain,
  /* .wots_chain = */ ascon_wots_chain,
  /* .fors_hash = */ ascon_fors_hash,
  /* .h_msg = */ ascon_h_msg,
  /* .prf = */ ascon_prf,
  /* .prf_msg = */ ascon_prf_msg,
  /* .h_f = */ ascon_f,
  /* .h_h = */ ascon_h,
  /* .h_t = */ ascon_t
};

const slh_param_t slh_dsa_ascon_192f = {
  /* .alg_id = */ "SLH-DSA-ASCON-192f",
  /* .n = */ 24,
  /* .h = */ 66,
  /* .d = */ 22,
  /* .hp = */ 3,
  /* .a = */ 8,
  /* .k = */ 33,
  /* .lg_w = */ 4,
  /* .m = */ 42,
  /* .mk_var = */ ascon_mk_var,
  /* .chain = */ ascon_chain,
  /* .wots_chain = */ ascon_wots_chain,
  /* .fors_hash = */ ascon_fors_hash,
  /* .h_msg = */ ascon_h_msg,
  /* .prf = */ ascon_prf,
  /* .prf_msg = */ ascon_prf_msg,
  /* .h_f = */ ascon_f,
  /* .h_h = */ ascon_h,
  /* .h_t = */ ascon_t
};

const slh_param_t slh_dsa_ascon_256s = {
  /* .alg_id = */ "SLH-DSA-ASCON-256s",
  /* .n = */ 32,
  /* .h = */ 64,
  /* .d = */ 8,
  /* .hp = */ 8,
  /* .a = */ 14,
  /* .k = */ 22,
  /* .lg_w = */ 4,
  /* .m = */ 47,
  /* .mk_var = */ ascon_mk_var,
  /* .chain = */ ascon_chain,
  /* .wots_chain = */ ascon_wots_chain,
  /* .fors_hash = */ ascon_fors_hash,
  /* .h_msg = */ ascon_h_msg,
  /* .prf = */ ascon_prf,
  /* .prf_msg = */ ascon_prf_msg,
  /* .h_f = */ ascon_f,
  /* .h_h = */ ascon_h,
  /* .h_t = */ ascon_t
};

const slh_param_t slh_dsa_ascon_256f = {
  /* .alg_id = */ "SLH-DSA-ASCON-256f",
  /* .n = */ 32,
  /* .h = */ 68,
  /* .d = */ 17,
  /* .hp = */ 4,
  /* .a = */ 9,
  /* .k = */ 35,
  /* .lg_w = */ 4,
  /* .m = */ 49,
  /* .mk_var = */ ascon_mk_var,
  /* .chain = */ ascon_chain,
  /* .wots_chain = */ ascon_wots_chain,
  /* .fors_hash = */ ascon_fors_hash,
  /* .h_msg = */ ascon_h_msg,
  /* .prf = */ ascon_prf,
  /* .prf_msg = */ ascon_prf_msg,
  /* .h_f = */ ascon_f,
  /* .h_h = */ ascon_h,
  /* .h_t = */ ascon_t
};
