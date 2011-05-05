/*
 * File: as-jelvm.c
 * Implements:
 *
 * Copyright: Jens Låås, 2011
 * Copyright license: According to GPL, see file COPYING in this directory.
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "jelist.h"

#include "jelvm-as.h"


struct ctx {
	uint8_t *data;
	int len;
};

struct jlhead *msgs;

void infofn(const char *s)
{
	jl_append(msgs, strdup(s));
}

int sgetcfn(void *ctx, char *buf)
{
	return read(0, buf, 1);
}

void oputcfn(void *ctx_in, int pos, uint8_t byte)
{
	uint8_t *p;
	struct ctx *ctx = ctx_in;
	
	if(pos >= ctx->len) {
		p = realloc(ctx->data, ctx->len+512);
		if(p) {
			ctx->len += 512;
			ctx->data = p;
		}
	}
	ctx->data[pos] = byte;
}

int main(int argc, char **argv)
{
	int len, rc;
	struct ctx ctx;
	char *s;
	int verbose=0, debug=0;

	if( (argc > 1) && (strcmp(argv[1], "-h")==0) ) {
		printf("as-jelvm [-h] [-v] [-D]\n"
		       "  -h  display this help\n"
		       "  -v  verbose\n"
		       "  -D  debugging information concerning the assembler\n"
		       "\n"
		       "as-jelvm reads assembler sourcecode from stdin.\n"
		       "Outputs compiled code to stdout.\n"
		       "Ex: as-jelvm < source.s > prg\n"
			"\n");
		exit(0);
	}

	if( (argc > 1) && (strcmp(argv[1], "-v")==0) ) {
		argc--;
		argv++;
		verbose=1;
	}
	if( (argc > 1) && (strcmp(argv[1], "-D")==0) ) {
		argc--;
		argv++;
		verbose=debug=1;
	}

	msgs = jl_new();
	
	ctx.data = malloc(8);
	ctx.len = 8;
	
	rc = jelvm_as(&len, infofn, sgetcfn, oputcfn, &ctx);
	if(rc==0) write(1, ctx.data, len);

	if(rc || verbose) {
		jl_foreach(msgs, s) {
			if(strncmp(s, "DBG", 3)||debug) {
				fprintf(stderr, "jelvm: '%s'\n", s);
			}
		}
	}

	return rc;
}
