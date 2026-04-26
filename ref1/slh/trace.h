#pragma once
#include <stdio.h>

#ifdef ENABLE_TRACE
void trace_init(const char *path);
void trace_close(void);
void trace_write(const char *event, const char *fmt, ...);
#else
static inline void trace_init(const char *path) {}
static inline void trace_close(void) {}
static inline void trace_write(const char *event, const char *fmt, ...) {}
#endif
