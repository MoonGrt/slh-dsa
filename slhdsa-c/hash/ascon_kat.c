#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

// #include "ascon_api.h"

// static void print_hex(const uint8_t *x, size_t x_sz) {
//   size_t i;
//   for (i = 0; i < x_sz; i++)
//     printf("%02X", x[i]);
//   printf("\n");
// }

// int main(void) {
//   uint8_t md[64];
//   uint8_t zero = 0;
//   ascon256(md, sizeof(md), NULL, 0);
//   print_hex(md, sizeof(md));
//   ascon256(md, sizeof(md), &zero, 1);
//   print_hex(md, sizeof(md));
//   return 0;
// }
