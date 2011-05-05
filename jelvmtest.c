/*
 * File: jelvmtest.c
 * Implements:
 *
 * Copyright: Jens Låås, 2011
 * Copyright license: According to GPL, see file COPYING in this directory.
 *
 */

#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "jelvm.h"

uint64_t extcall(uint64_t *regs)
{
	printf("External call! %llu %llu\n", regs[0], regs[1]);
	return 0;
}

void infofn(const char *s)
{
	printf("info from jelvm: '%s'\n", s);
}

int main(int argc, char **argv)
{
	uint64_t iv[1];

	iv[0] = extcall;

	uint8_t code[] = { 
		'J', 'E', 'L', 'V', 0, 0,
		OP_SET, 8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 111,
		OP_CALL, 0, 0, 0, 
		OP_SYSCALL, 0, 0, SYSCALL_getpid,
		OP_SET, 8, 0, 2, 0, 0, 0, 0, 0, 0, 0, 1,
		OP_SET, 8, 0, 4, 0, 0, 0, 0, 0, 0, 0, 4,
		OP_ADDROF, 8, 0, 3, 0, 0, 0, 0, 0, 0, 0, 24,
		OP_SYSCALL, 3, (SYSCALL_write & 0xff00) >> 8, SYSCALL_write & 0xff,
		OP_EXIT, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		'H', 'E', 'J', '\n', 0
	};
	return jelvm_exec(code, iv, 1, JELVM_TRACE|JELVM_DEBUG, infofn);
}
