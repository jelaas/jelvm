#ifndef JELVM_AS_H
#define JELVM_AS_H

int jelvm_as(int *len, void (*info)(const char *istr), int (*sgetc)(void *ctx, char *buf), void (*putc)(void *ctx, int pos, uint8_t byte), void *ctx);

#endif
