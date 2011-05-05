/*
 * File: jelvmcli.c
 * Implements:
 *
 * Copyright: Jens Låås, 2011
 * Copyright license: According to GPL, see file COPYING in this directory.
 *
 */

#include <arpa/inet.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "jelvm.h"

void infofn(const char *s)
{
	printf("jelvm: '%s'\n", s);
}

int main(int argc, char **argv, char **envp)
{
	uint64_t iv[3];
	void *code;
	char buf[4096];
	size_t codesize = 0;
	size_t allocsize = 4096;
	unsigned int flags=0;
	ssize_t n;
	int fd = 0;

	if( (argc > 1) && (strcmp(argv[1], "-h")==0) ) {
		printf("jelvm [-h] [-v] [-D] [program]\n"
		       "  -h  display this help\n"
		       "  -v  verbose\n"
		       "  -D  debugging information concerning the virtual machine\n"
		       "\n"
		       "jelvm reads compiled code from <program> or from stdin.\n"
		       "Execution via the #! format is supported.\n"
		       "\n");
		exit(0);
	}

	if(argc > 1) {
		if(strcmp(argv[1], "-v")==0) {
			flags |= JELVM_TRACE;
			argc--;
			argv++;
		}
	}
	if(argc > 1) {
		if(strcmp(argv[1], "-D")==0) {
			flags |= (JELVM_TRACE|JELVM_DEBUG);
			argc--;
			argv++;
		}
	}

	if(argc > 1) {
		fd = open(argv[1], O_RDONLY);
		if(fd == -1) exit(2);
	}
	
	code = malloc(allocsize);
	while( (n = read(fd, buf, sizeof(buf))) > 0 ) {
		if( (codesize + n) >= allocsize ) {
			code = realloc(code, allocsize + 4096);
			if(!code) {
				fprintf(stderr, "Failed to alloc memory for code.\n");
				exit(2);
			}
			allocsize += 4096;
		}
		memcpy(code + codesize, buf, n);
		codesize += n;
	}
	
	if(fd!=0) close(fd);

	if(memcmp(code, "#!", 2)==0) {
		void *p;
		p = strchr(code, '\n');
		if(p) {
			code = p+1;
		}
	}
	
	if(flags & JELVM_DEBUG) printf("code size: %d\n", n);

	iv[0] = argc;
	iv[1] = argv;
	iv[2] = envp;

	return jelvm_exec(code, iv, 3, flags, infofn);
}
