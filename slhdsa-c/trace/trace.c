#include "trace.h"

cJSON *trace_root;
cJSON *current_node;
cJSON *node_stack[MAX_DEPTH];
const char *trace_file = NULL;
FILE *trace_fp = NULL;
int trace_depth = 0;
int trace_level = 0;
int trace_step = 0;
char level_name[64];
extern const slh_param_t *prm;

void trace_init(const char *path) {
  trace_fp = fopen(path, "w");
  trace_root = cJSON_CreateObject();
  current_node = trace_root;
  node_stack[0] = trace_root;
  cJSON_AddItemToObject(trace_root, "info", cJSON_CreateObject());
  cJSON_AddItemToObject(trace_root, "data", cJSON_CreateObject());
  cJSON_AddNumberToObject(INFO_NODE, "level", trace_level);
}

void trace_close(void) {
  trace_write("%s\n", cJSON_Print(trace_root));
  cJSON_Delete(trace_root);
  if (trace_fp) fclose(trace_fp);
}

void trace_write(const char *fmt, ...) {
  if (!trace_fp) return;
  va_list args;
  va_start(args, fmt);
  vfprintf(trace_fp, fmt, args);
  fflush(trace_fp);
  va_end(args);
}

void trace_push_level(const char *name) {
  if (!TRACEEN) return;
  if (!current_node) return;
  trace_level++;
  cJSON *children = cJSON_GetObjectItem(current_node, "children");
  if (!children) {
    children = cJSON_CreateArray();
    cJSON_AddItemToObject(current_node, "children", children);
  }
  cJSON *child = cJSON_CreateObject();
  cJSON *info = cJSON_CreateObject();
  cJSON *data = cJSON_CreateObject();
  cJSON_AddNumberToObject(info, "level", trace_level);
  cJSON_AddStringToObject(info, "name", name);
  cJSON_AddItemToObject(child, "info", info);
  cJSON_AddItemToObject(child, "data", data);
  cJSON_AddItemToObject(child, "children", cJSON_CreateArray());
  cJSON_AddItemToArray(children, child);
  current_node = child;
  node_stack[trace_level] = child;
}

void trace_pop_level(void) {
  if (!TRACEEN) return;
  if (trace_level <= 0) return;
  trace_level--;
  current_node = node_stack[trace_level];
}

void trace_hash(const char *name) {
  if (!TRACEEN) return;
  if (!current_node) return;
  trace_level++;
  trace_step++;
  cJSON *children = cJSON_GetObjectItem(current_node, "children");
  if (!children) {
    children = cJSON_CreateArray();
    cJSON_AddItemToObject(current_node, "children", children);
  }
  cJSON *child = cJSON_CreateObject();
  cJSON *info = cJSON_CreateObject();
  cJSON *data = cJSON_CreateObject();
  cJSON_AddNumberToObject(info, "level", trace_level);
  cJSON_AddNumberToObject(info, "step", trace_step);
  cJSON_AddStringToObject(info, "name", name);
  cJSON_AddItemToObject(child, "info", info);
  cJSON_AddItemToObject(child, "data", data);
  cJSON_AddItemToArray(children, child);
  current_node = child;
  node_stack[trace_level] = child;
}

void trace_add_hex(cJSON *obj, const char *name,
                   const uint8_t *buf, size_t len) {
  static const char hex[] = "0123456789abcdef";
  char *s = malloc(len * 2 + 1);
  for (size_t i = 0; i < len; i++) {
    s[i * 2 + 0] = hex[(buf[i] >> 4) & 0xF];
    s[i * 2 + 1] = hex[buf[i] & 0xF];
  }
  s[len * 2] = 0;
  cJSON_AddStringToObject(obj, name, s);
  free(s);
}

void trace_add_u32(cJSON *obj, const char *name, uint32_t v) {
  cJSON_AddNumberToObject(obj, name, (double)v);
}

void trace_add_str(cJSON *obj, const char *name, const char *s) {
  cJSON_AddStringToObject(obj, name, s);
}

static const char *adrs_type_name(uint32_t t) {
  switch (t) {
    case 0: return "0 - WOTS_HASH";
    case 1: return "1 - WOTS_PK";
    case 2: return "2 - TREE";
    case 3: return "3 - FORS_TREE";
    case 4: return "4 - FORS_ROOTS";
    case 5: return "5 - WOTS_PRF";
    case 6: return "6 - FORS_PRF";
    default: return "UNKNOWN";
  }
}

static inline uint32_t adrs_u32(const uint8_t *a, int i) {
  a += i * 4;
  return ((uint32_t)a[0] << 24) | ((uint32_t)a[1] << 16) |
         ((uint32_t)a[2] << 8) | ((uint32_t)a[3]);
}
void trace_add_adrs(cJSON *obj, const uint8_t *adrs) {
  uint32_t a[8];
  for (int i = 0; i < 8; i++)
    a[i] = adrs_u32(adrs, i);

  // printf("a[0]: %08x\n", a[0]);
  // printf("a[1]: %08x\n", a[1]);
  // printf("a[2]: %08x\n", a[2]);
  // printf("a[3]: %08x\n", a[3]);
  // printf("a[4]: %08x\n", a[4]);
  // printf("a[5]: %08x\n", a[5]);
  // printf("a[6]: %08x\n", a[6]);
  // printf("a[7]: %08x\n", a[7]);
  // exit(0);

  cJSON *d = cJSON_CreateObject();
  uint32_t layer = a[0];
  uint32_t tree0 = a[1];
  uint32_t tree1 = a[2];
  uint32_t tree2 = a[3];
  uint32_t type = a[4];
  uint32_t keypair = a[5];
  uint32_t padding0 = a[6];
  uint32_t padding1 = a[7];
  char tree_str[32];
  snprintf(tree_str, sizeof(tree_str), "%08x%08x%08x", 
           tree0, tree1, tree2);
  char padding_str[32];
  snprintf(padding_str, sizeof(padding_str), "%08x%08x", 
           padding0, padding1);
  trace_add_hex(d, "raw", adrs, 32);
  cJSON_AddNumberToObject(d, "layer", layer);
  cJSON_AddStringToObject(d, "tree", tree_str);
  cJSON_AddStringToObject(d, "type", adrs_type_name(type));
  cJSON_AddNumberToObject(d, "keypair", keypair);
  switch (type) {
    case 0: /* WOTS_HASH */
      cJSON_AddNumberToObject(d, "chain", a[6]);
      cJSON_AddNumberToObject(d, "hash", a[7]);
      break;
    case 1: /* WOTS_PK */
      cJSON_AddStringToObject(d, "padding", padding_str);
      break;
    case 2: /* TREE */
      cJSON_AddNumberToObject(d, "tree height", a[6]);
      cJSON_AddNumberToObject(d, "tree index", a[7]);
      break;
    case 3: /* FORS_TREE */
      cJSON_AddNumberToObject(d, "tree height", a[6]);
      cJSON_AddNumberToObject(d, "tree index", a[7]);
      break;
    case 4: /* FORS_ROOTS */
      cJSON_AddStringToObject(d, "padding", padding_str);
      break;
    case 5: /* WOTS_PRF */
      cJSON_AddNumberToObject(d, "chain", a[6]);
      cJSON_AddNumberToObject(d, "hash", a[7]);
      break;
    case 6: /* FORS_PRF */
      cJSON_AddNumberToObject(d, "tree height", a[6]);
      cJSON_AddNumberToObject(d, "tree index", a[7]);
      break;
  }
  cJSON_AddItemToObject(obj, "adrs", d);
}