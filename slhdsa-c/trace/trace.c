#include "trace.h"

cJSON *trace_root;
cJSON *current_node;
cJSON *node_stack[MAX_DEPTH];
const char *trace_file = NULL;
FILE *trace_fp = NULL;
int trace_depth = 0;
int trace_level = 0;
char level_name[64];

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
  if (trace_level <= 0) return;
  trace_level--;
  current_node = node_stack[trace_level];
}

void trace_hash(void) {

}
