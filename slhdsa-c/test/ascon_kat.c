#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ascon_api.h"

static void kat_hex(FILE *fh, const char *label, const uint8_t *x, size_t xlen) {
  size_t i;
  fprintf(fh, "%s = ", label);
  for (i = 0; i < xlen; i++)
    fprintf(fh, "%02X", x[i]);
  fprintf(fh, "\n");
}

static int hex_digit(int ch) {
  if (ch >= '0' && ch <= '9')
    return ch - '0';
  if (ch >= 'a' && ch <= 'f')
    return ch - 'a' + 10;
  if (ch >= 'A' && ch <= 'F')
    return ch - 'A' + 10;
  return -1;
}

static uint8_t *hex_data(size_t *data_sz, const char *hex) {
  int ch, cl;
  size_t i, l;
  uint8_t *buf;

  if (hex == NULL || data_sz == NULL)
    return NULL;
  *data_sz = 0;
  l = strlen(hex);

  /* need even number of digits */
  if (l % 2 != 0)
    return NULL;
  l /= 2;
  buf = malloc(l);
  if (buf == NULL) {
    perror("malloc()");
    exit(-1);
  }
  for (i = 0; i < l; i++) {
    ch = hex_digit(hex[2 * i]);
    cl = hex_digit(hex[2 * i + 1]);
    if (ch < 0 || cl < 0) {
      free(buf);
      return NULL;
    }
    buf[i] = (ch << 4) | cl;
  }
  *data_sz = l;
  return buf;
}

const char usage[] = "ascon_kat -<inputs> <data>\n";
char *data_args[][2] = {
  {"message", NULL},
  {"anwser", NULL},
  {"tcId", NULL},
  {NULL, NULL},
};

static const char *find_par(const char *name) {
  int i;
  for (i = 0; data_args[i][0] != NULL; i++)
    if (strcmp(data_args[i][0], name) == 0)
      return data_args[i][1];
  return NULL;
}

static void parse_args(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "%s", usage);
    exit(1);
  }

  int i, j;
  int arg_ok = 0;
  /* parse arguments */
  for (i = 1; i < argc; i++) {
    arg_ok = 0;
    if (argv[i][0] == '-') {
      /* parameters */
      for (j = 0; data_args[j][0] != NULL; j++) {
        if (strcmp(data_args[j][0], &argv[i][1]) == 0) {
          if (data_args[j][1] != NULL) {
            fprintf(stderr, "%s: %s set twice.\n", argv[0], argv[i]);
            exit(1);
          }
          if (i + 1 >= argc) {
            fprintf(stderr, "%s: %s parameter missing.\n", argv[0], argv[i]);
            exit(1);
          }
          i++;
          data_args[j][1] = argv[i];
          arg_ok = 1;
          break;
        }
      }
    }
    if (!arg_ok) {
      fprintf(stderr, "%s: unknown argument %s\n", argv[0], argv[i]);
      exit(1);
    }
  }
}

int main(int argc, char **argv) {
  parse_args(argc, argv);

  uint8_t *message = NULL;
  size_t message_sz = 0;
  message = hex_data(&message_sz, find_par("message"));

  uint8_t md[64];
  ascon256(md, sizeof(md), message, message_sz);

  uint8_t *anwser = NULL;
  size_t anwser_sz = 0;
  anwser = hex_data(&anwser_sz, find_par("anwser"));
  int fail = 0;
  if (anwser == NULL)
    kat_hex(stdout, "md", md, 64);
  else
    if (memcmp(anwser, md, anwser_sz) != 0)
      fail++;

  if (fail > 0)
    printf("[FAIL] %s\n", find_par("message"));
  else
    printf("[PASS] %s\n", find_par("message"));

  return 0;
}
