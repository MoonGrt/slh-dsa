//  slh_ascon.c

//  === Portable C code: Functions for instantiation of SLH-DSA with ASCON

#ifndef SLOTH_ASCON

#include "slh_ctx.h"
#include "sha3_api.h"
#include "slh_adrs.h"

//  === 10.1.   SLH-DSA Using ASCON

//  Hmsg(R, PK.seed, PK.root, M) = ASCON256(R || PK.seed || PK.root || M, 8m)

static void ascon_h_msg( slh_ctx_t *ctx,
                            uint8_t *h,
                            const uint8_t *r,
                            const uint8_t *m, size_t m_sz)
{
    sha3_ctx_t sha3;
    size_t  n = ctx->prm->n;

    ascon256_init(&sha3);
    ascon_update(&sha3, r, n);
    ascon_update(&sha3, ctx->pk_seed, n);
    ascon_update(&sha3, ctx->pk_root, n);
    ascon_update(&sha3, m, m_sz);

    ascon_out(&sha3, h, ctx->prm->m);
}

//  F(PK.seed, ADRS, M1 ) = ASCON256(PK.seed || ADRS || M1, 8n)

static void ascon_f( slh_ctx_t *ctx,
                        uint8_t *h,
                        const uint8_t *m1)
{
    sha3_ctx_t sha3;
    size_t  n = ctx->prm->n;

    ascon256_init(&sha3);
    ascon_update(&sha3, ctx->pk_seed, n);
    ascon_update(&sha3, (const uint8_t *) ctx->adrs->u8, 32);
    ascon_update(&sha3, m1, n);

    ascon_out(&sha3, h, n);
}

//  PRF(PK.seed, SK.seed, ADRS) = ASCON256(PK.seed || ADRS || SK.seed, 8n)

static void ascon_prf(slh_ctx_t *ctx, uint8_t *h)
{
    ascon_f(ctx, h, ctx->sk_seed);
}


//  PRFmsg (SK.prf, opt_rand, M) = ASCON256(SK.prf || opt_rand || M, 8n)

static void ascon_prf_msg(  slh_ctx_t *ctx,
                                uint8_t *h, const uint8_t *opt_rand,
                                const uint8_t *m, size_t m_sz)
{
    sha3_ctx_t sha3;
    size_t  n = ctx->prm->n;

    ascon256_init(&sha3);
    ascon_update(&sha3, ctx->sk_prf, n);
    ascon_update(&sha3, opt_rand, n);
    ascon_update(&sha3, m, m_sz);

    ascon_out(&sha3, h, n);
}

//  T_l(PK.seed, ADRS, M ) = ASCON256(PK.seed || ADRS || Ml, 8n)

static void ascon_t( slh_ctx_t *ctx,
                        uint8_t *h, const uint8_t *m, size_t m_sz)
{
    sha3_ctx_t sha3;
    size_t  n = ctx->prm->n;

    ascon256_init(&sha3);
    ascon_update(&sha3, ctx->pk_seed, n);
    ascon_update(&sha3, (const uint8_t *) ctx->adrs->u8, 32);
    ascon_update(&sha3, m, m_sz);

    ascon_out(&sha3, h, n);
}


//  H(PK.seed, ADRS, M2 ) = ASCON256(PK.seed || ADRS || M2, 8n)

static void ascon_h( slh_ctx_t *ctx,
                        uint8_t *h,
                        const uint8_t *m1, const uint8_t *m2)
{
    sha3_ctx_t sha3;
    size_t  n = ctx->prm->n;

    ascon256_init(&sha3);
    ascon_update(&sha3, ctx->pk_seed, n);
    ascon_update(&sha3, (const uint8_t *) ctx->adrs->u8, 32);
    ascon_update(&sha3, m1, n);
    ascon_update(&sha3, m2, n);

    ascon_out(&sha3, h, n);
}

//  create a context

static void ascon_mk_ctx(slh_ctx_t *ctx,
                         const uint8_t *pk, const uint8_t *sk,
                         const slh_param_t *prm)
{
    size_t n = prm->n;

    ctx->prm = prm;     //  store fixed parameters
    if (sk != NULL) {
        memcpy( ctx->sk_seed,   sk,         n );
        memcpy( ctx->sk_prf,    sk + n,     n );
        memcpy( ctx->pk_seed,   sk + 2*n,   n );
        memcpy( ctx->pk_root,   sk + 3*n,   n );
    } else  if (pk != NULL) {
        memcpy( ctx->pk_seed,   pk,         n );
        memcpy( ctx->pk_root,   pk + n,     n );
    }

    //  local ADRS buffer
    ctx->adrs = &ctx->t_adrs;
}

//  === Chaining function used in WOTS+
//  Algorithm 4: chain(X, i, s, PK.seed, ADRS)

//  chaining by processor (some optimizations)

static void ascon_chain( slh_ctx_t *ctx, uint8_t *tmp, const uint8_t *x,
                            uint32_t i, uint32_t s)
{
    uint32_t j, k;
    uint64_t ks[25];
    size_t n = ctx->prm->n;

    if (s == 0) {                           //  no-op
        memcpy(tmp, x, n);
        return;
    }

    const uint32_t r = (1600-256*2)/64;     //  ASCON256 rate
    uint32_t n8 = n / 8;                    //  number of words
    uint32_t h = n8 + (32 / 8);             //  static part len
    uint32_t l = h + n8;                    //  input length

    memcpy(ks + h, x, n);                   //  start node
    for (j = 0; j < s; j++) {
        if (j > 0) {
            memcpy(ks + h, ks, n);          //  chaining
        }
        memcpy(ks, ctx->pk_seed, n);        //  PK.seed
        adrs_set_hash_address(ctx, i + j);  //  address
        memcpy(ks + n8, (const uint8_t *) ctx->adrs->u8, 32);

        //  padding
        ks[l] = 0x1F;                       //  ascon padding
        for (k = l + 1; k < r - 1; k++) {
            ks[k] = 0;
        }
        ks[r - 1] = UINT64_C(1) << 63;      //  rate padding
        for (k = r; k < 25; k++) {
            ks[k] = 0;
        }

        // ascon_f1600(ks);                   //  permutation
    }
    memcpy(tmp, ks, n);
}

//  Combination WOTS PRF + Chain

static void ascon_wots_chain( slh_ctx_t *ctx, uint8_t *tmp, uint32_t s)
{
    //  PRF secret key
    adrs_set_type(ctx, ADRS_WOTS_PRF);
    adrs_set_tree_index(ctx, 0);
    ascon_prf(ctx, tmp);

    //  chain
    adrs_set_type(ctx, ADRS_WOTS_HASH);
    ascon_chain( ctx, tmp, tmp, 0, s);
}

//  Combination FORS PRF + F (if s == 1)

static void ascon_fors_hash( slh_ctx_t *ctx, uint8_t *tmp, uint32_t s)
{
    //  PRF secret key
    adrs_set_type(ctx, ADRS_FORS_PRF);
    adrs_set_tree_height(ctx, 0);
    ascon_prf(ctx, tmp);

    //  hash it again
    if (s == 1) {
        adrs_set_type(ctx, ADRS_FORS_TREE);
        ascon_f(ctx, tmp, tmp);
    }
}

//  parameter sets

const slh_param_t slh_dsa_ascon_128s = {    .alg_id ="SLH-DSA-ASCON-128s",
    .n= 16, .h= 63, .d= 7, .hp= 9, .a= 12, .k= 14, .lg_w= 4, .m= 30,
    .mk_ctx= ascon_mk_ctx, .chain= ascon_chain,
    .wots_chain= ascon_wots_chain, .fors_hash= ascon_fors_hash,
    .h_msg= ascon_h_msg, .prf= ascon_prf, .prf_msg= ascon_prf_msg,
    .h_f= ascon_f, .h_h= ascon_h, .h_t= ascon_t
};

const slh_param_t slh_dsa_ascon_128f = {    .alg_id ="SLH-DSA-ASCON-128f",
    .n= 16, .h= 66, .d= 22, .hp= 3, .a= 6, .k= 33, .lg_w= 4, .m= 34,
    .mk_ctx= ascon_mk_ctx, .chain= ascon_chain,
    .wots_chain= ascon_wots_chain, .fors_hash= ascon_fors_hash,
    .h_msg= ascon_h_msg, .prf= ascon_prf, .prf_msg= ascon_prf_msg,
    .h_f= ascon_f, .h_h= ascon_h, .h_t= ascon_t
};

const slh_param_t slh_dsa_ascon_192s = {    .alg_id ="SLH-DSA-ASCON-192s",
    .n= 24, .h= 63, .d= 7, .hp= 9, .a= 14, .k= 17, .lg_w= 4, .m= 39,
    .mk_ctx= ascon_mk_ctx, .chain= ascon_chain,
    .wots_chain= ascon_wots_chain, .fors_hash= ascon_fors_hash,
    .h_msg= ascon_h_msg, .prf= ascon_prf, .prf_msg= ascon_prf_msg,
    .h_f= ascon_f, .h_h= ascon_h, .h_t= ascon_t
};

const slh_param_t slh_dsa_ascon_192f = {    .alg_id ="SLH-DSA-ASCON-192f",
    .n= 24, .h= 66, .d= 22, .hp= 3, .a= 8, .k= 33, .lg_w= 4, .m= 42,
    .mk_ctx= ascon_mk_ctx, .chain= ascon_chain,
    .wots_chain= ascon_wots_chain, .fors_hash= ascon_fors_hash,
    .h_msg= ascon_h_msg, .prf= ascon_prf, .prf_msg= ascon_prf_msg,
    .h_f= ascon_f, .h_h= ascon_h, .h_t= ascon_t
};

const slh_param_t slh_dsa_ascon_256s = {    .alg_id ="SLH-DSA-ASCON-256s",
    .n= 32, .h= 64, .d= 8, .hp= 8, .a= 14, .k= 22, .lg_w= 4, .m= 47,
    .mk_ctx= ascon_mk_ctx, .chain= ascon_chain,
    .wots_chain= ascon_wots_chain, .fors_hash= ascon_fors_hash,
    .h_msg= ascon_h_msg, .prf= ascon_prf, .prf_msg= ascon_prf_msg,
    .h_f= ascon_f, .h_h= ascon_h, .h_t= ascon_t
};

const slh_param_t slh_dsa_ascon_256f = {    .alg_id ="SLH-DSA-ASCON-256f",
    .n= 32, .h= 68, .d= 17, .hp= 4, .a= 9, .k= 35, .lg_w= 4, .m= 49,
    .mk_ctx= ascon_mk_ctx, .chain= ascon_chain,
    .wots_chain= ascon_wots_chain, .fors_hash= ascon_fors_hash,
    .h_msg= ascon_h_msg, .prf= ascon_prf, .prf_msg= ascon_prf_msg,
    .h_f= ascon_f, .h_h= ascon_h, .h_t= ascon_t
};

//  no SLOTH_ASCON
#endif
