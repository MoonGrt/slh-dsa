#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>

#include "slh_param.h"
#include "slh_var.h"
#include "cJSON.h"

#define MAX_DEPTH 128
extern cJSON *current_node;
extern cJSON *node_stack[MAX_DEPTH];
extern cJSON *trace_root;
extern const char *trace_file;
extern FILE *trace_fp;
extern int trace_depth;
extern int trace_level;
extern int trace_step;
extern char level_name[64];

typedef enum {
  TRACE_TYPE_STRING,
  TRACE_TYPE_NUMBER,
  TRACE_TYPE_BOOL,
  TRACE_TYPE_NULL
} trace_type_t;

void trace_init(const char *path);
void trace_close(void);
void trace_write(const char *fmt, ...);
void trace_push_level(const char *name);
void trace_pop_level(void);
void trace_hash(const char *name);

void trace_add_hex(cJSON *obj, const char *name, const uint8_t *buf,
                   size_t len);
void trace_add_u32(cJSON *obj, const char *name, uint32_t v);
void trace_add_str(cJSON *obj, const char *name, const char *s);
void trace_add_adrs(cJSON *obj, const uint8_t *adrs);



#define TRACEEN (trace_depth > 0) && (trace_depth > trace_level)
#define TRACE(expr) \
  do { \
    if (TRACEEN) { \
      expr; \
    } \
  } while (0)
#define TRACE_RETN(name, expr) __extension__ ({ \
  trace_push_level(name); \
  __auto_type _r = (expr); \
  trace_pop_level(); \
  _r; \
})
#define TRACE_VOID(name, expr) __extension__ ({ \
  trace_push_level(name); \
  expr; \
  trace_pop_level(); \
})
#define INFO_NODE cJSON_GetObjectItem(current_node, "info")
#define DATA_NODE cJSON_GetObjectItem(current_node, "data")

/*
#define TRACE_MK_VAR(prm, var, pk, sk) do { \
    (prm)->mk_var(var, pk, sk, prm); \
    if (TRACEEN) {  \
    } \
  } while (0)
*/
#define TRACE_CHAIN(prm, var, tmp, x, i, s) do { \
    (prm)->chain(var, tmp, x, i, s); \
    if (TRACEEN) {  \
      trace_hash("chain"); \
      trace_add_adrs(DATA_NODE, var->adrs->u8); \
      trace_add_hex(DATA_NODE, "x", x, var->prm->n); \
      trace_add_u32(DATA_NODE, "i", i); \
      trace_add_u32(DATA_NODE, "s", s); \
      trace_add_hex(DATA_NODE, "out", tmp, var->prm->n); \
      trace_pop_level(); \
    } \
  } while (0)
#define TRACE_WOTS_CHAIN(prm, var, tmp, s) do { \
    (prm)->wots_chain(var, tmp, s); \
    if (TRACEEN) {  \
      trace_hash("wots_chain"); \
      trace_add_adrs(DATA_NODE, var->adrs->u8); \
      trace_add_u32(DATA_NODE, "s", s); \
      trace_add_hex(DATA_NODE, "out", tmp, var->prm->n); \
      trace_pop_level(); \
    } \
  } while (0)
#define TRACE_FORS_HASH(prm, var, tmp, s) do { \
    (prm)->fors_hash(var, tmp, s); \
    if (TRACEEN) {  \
      trace_hash("fors_hash"); \
      trace_add_adrs(DATA_NODE, var->adrs->u8); \
      trace_add_u32(DATA_NODE, "s", s); \
      trace_add_hex(DATA_NODE, "out", tmp, var->prm->n); \
      trace_pop_level(); \
    } \
  } while (0)
#define TRACE_H_MSG(prm, var, h, r, m, m_sz, ctx, ctx_sz) do { \
    (prm)->h_msg(var, h, r, m, m_sz, ctx, ctx_sz); \
    if (TRACEEN) {  \
      trace_hash("h_msg"); \
      trace_add_hex(DATA_NODE, "r", r, (var)->prm->n); \
      trace_add_hex(DATA_NODE, "m", m, m_sz); \
      if (ctx && ctx_sz) \
        trace_add_hex(DATA_NODE, "ctx", ctx, ctx_sz); \
      trace_add_hex(DATA_NODE, "out", h, (var)->prm->m); \
      trace_pop_level(); \
    } \
  } while (0)
#define TRACE_PRF(prm, var, h) do { \
    (prm)->prf(var, h); \
    if (TRACEEN) {  \
      trace_hash("prf"); \
      trace_add_adrs(DATA_NODE, var->adrs->u8); \
      trace_add_hex(DATA_NODE, "skseed", var->sk_seed, var->prm->n); \
      trace_add_hex(DATA_NODE, "out", h, var->prm->n); \
      trace_pop_level(); \
    } \
  } while (0)
#define TRACE_PRF_MSG(prm, var, h, opt_rand, m, m_sz, ctx, ctx_sz) do { \
    (prm)->prf_msg(var, h, opt_rand, m, m_sz, ctx, ctx_sz); \
    if (TRACEEN) {  \
      trace_hash("prf_msg"); \
      trace_add_hex(DATA_NODE, "opt_rand", opt_rand, (var)->prm->n); \
      trace_add_hex(DATA_NODE, "m", m, m_sz); \
      if (ctx && ctx_sz) \
        trace_add_hex(DATA_NODE, "ctx", ctx, ctx_sz); \
      trace_add_hex(DATA_NODE, "out", h, (var)->prm->m); \
      trace_pop_level(); \
    } \
  } while (0)
#define TRACE_H_F(prm, var, h, m1) do { \
    (prm)->h_f(var, h, m1); \
    if (TRACEEN) {  \
      trace_hash("h_f"); \
      trace_add_adrs(DATA_NODE, var->adrs->u8); \
      trace_add_hex(DATA_NODE, "m1", m1, var->prm->n); \
      trace_add_hex(DATA_NODE, "out", h, var->prm->n); \
      trace_pop_level(); \
    } \
  } while (0)
#define TRACE_H_H(prm, var, h, m1, m2) do { \
    (prm)->h_h(var, h, m1, m2); \
    if (TRACEEN) {  \
      trace_hash("h_h"); \
      trace_add_adrs(DATA_NODE, var->adrs->u8); \
      trace_add_hex(DATA_NODE, "m1", m1, var->prm->n); \
      trace_add_hex(DATA_NODE, "m2", m2, var->prm->n); \
      trace_add_hex(DATA_NODE, "out", h, var->prm->n); \
      trace_pop_level(); \
    } \
  } while (0)
#define TRACE_H_T(prm, var, h, m, m_sz) do { \
    (prm)->h_t(var, h, m, m_sz); \
    if (TRACEEN) {  \
      trace_hash("h_t"); \
      trace_add_adrs(DATA_NODE, var->adrs->u8); \
      trace_add_hex(DATA_NODE, "msg", m, m_sz); \
      trace_add_hex(DATA_NODE, "out", h, var->prm->n); \
      trace_pop_level(); \
    } \
  } while (0)
