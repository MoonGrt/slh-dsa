#include <stdio.h>
#include <stdarg.h>

#include "cJSON.h"

#define MAX_DEPTH 128
extern cJSON *current_node;
extern cJSON *node_stack[MAX_DEPTH];
extern cJSON *trace_root;
extern const char *trace_file;
extern FILE *trace_fp;
extern int trace_depth;
extern int trace_level;
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
void trace_hash(void);

#define TRACEEN (trace_depth > 0) && (trace_depth > trace_level)
#define TRACE(expr) if (TRACEEN) expr;
#define LEVEL_RETN(name, expr) __extension__ ({ \
  trace_push_level(name);               \
  __auto_type _r = (expr);              \
  trace_pop_level();                    \
  _r;                                   \
})
#define LEVEL_VOID(name, expr) __extension__ ({ \
  trace_push_level(name);               \
  expr;                                 \
  trace_pop_level();                    \
})
#define INFO_NODE cJSON_GetObjectItem(current_node, "info")
#define DATA_NODE cJSON_GetObjectItem(current_node, "data")
#define HASH 
