#ifdef ENABLE_TRACE

#include <stdio.h>
#include <stdarg.h>
#include "trace.h"

static FILE *trace_fp = NULL;

void trace_init(const char *path) {
    trace_fp = fopen(path, "w");
}

void trace_close(void) {
    if (trace_fp) fclose(trace_fp);
}

void trace_write(const char *event, const char *fmt, ...) {
    if (!trace_fp) return;

    fprintf(trace_fp, "{\"event\":\"%s\",", event);

    va_list ap;
    va_start(ap, fmt);
    vfprintf(trace_fp, fmt, ap);
    va_end(ap);

    fprintf(trace_fp, "}\n");
}

#endif
