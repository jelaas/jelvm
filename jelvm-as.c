/*
 * File: jelvm-as.c
 * Implements:
 *
 * Copyright: Jens Låås, 2010
 * Copyright license: According to GPL, see file COPYING in this directory.
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "jelist.h"

#include "jelvm.h"

#define JELVM_MAJOR 0
#define JELVM_MINOR 0

enum {
	WHITE, LABEL, OP, SIZE, WHITEOP, ARG, REG, STRING
};

static char *syscalls[] = {
  "_llseek",
  "_newselect",
  "_sysctl",
  "access",
  "acct",
  "add_key",
  "adjtimex",
  "afs_syscall",
  "alarm",
  "bdflush",
  "break",
  "brk",
  "capget",
  "capset",
  "chdir",
  "chmod",
  "chown",
  "chown32",
  "chroot",
  "clock_getres",
  "clock_gettime",
  "clock_nanosleep",
  "clock_settime",
  "clone",
  "close",
  "creat",
  "create_module",
  "delete_module",
  "dup",
  "dup2",
  "dup3",
  "epoll_create",
  "epoll_create1",
  "epoll_ctl",
  "epoll_pwait",
  "epoll_wait",
  "eventfd",
  "eventfd2",
  "execve",
  "exit",
  "exit_group",
  "faccessat",
  "fadvise64",
  "fadvise64_64",
  "fallocate",
  "fchdir",
  "fchmod",
  "fchmodat",
  "fchown",
  "fchown32",
  "fchownat",
  "fcntl",
  "fcntl64",
  "fdatasync",
  "fgetxattr",
  "flistxattr",
  "flock",
  "fork",
  "fremovexattr",
  "fsetxattr",
  "fstat",
  "fstat64",
  "fstatat64",
  "fstatfs",
  "fstatfs64",
  "fsync",
  "ftime",
  "ftruncate",
  "ftruncate64",
  "futex",
  "futimesat",
  "get_kernel_syms",
  "get_mempolicy",
  "get_robust_list",
  "get_thread_area",
  "getcpu",
  "getcwd",
  "getdents",
  "getdents64",
  "getegid",
  "getegid32",
  "geteuid",
  "geteuid32",
  "getgid",
  "getgid32",
  "getgroups",
  "getgroups32",
  "getitimer",
  "getpgid",
  "getpgrp",
  "getpid",
  "getpmsg",
  "getppid",
  "getpriority",
  "getresgid",
  "getresgid32",
  "getresuid",
  "getresuid32",
  "getrlimit",
  "getrusage",
  "getsid",
  "gettid",
  "gettimeofday",
  "getuid",
  "getuid32",
  "getxattr",
  "gtty",
  "idle",
  "init_module",
  "inotify_add_watch",
  "inotify_init",
  "inotify_init1",
  "inotify_rm_watch",
  "io_cancel",
  "io_destroy",
  "io_getevents",
  "io_setup",
  "io_submit",
  "ioctl",
  "ioperm",
  "iopl",
  "ioprio_get",
  "ioprio_set",
  "ipc",
  "kexec_load",
  "keyctl",
  "kill",
  "lchown",
  "lchown32",
  "lgetxattr",
  "link",
  "linkat",
  "listxattr",
  "llistxattr",
  "lock",
  "lookup_dcookie",
  "lremovexattr",
  "lseek",
  "lsetxattr",
  "lstat",
  "lstat64",
  "madvise",
  "madvise1",
  "mbind",
  "migrate_pages",
  "mincore",
  "mkdir",
  "mkdirat",
  "mknod",
  "mknodat",
  "mlock",
  "mlockall",
  "mmap",
  "mmap2",
  "modify_ldt",
  "mount",
  "move_pages",
  "mprotect",
  "mpx",
  "mq_getsetattr",
  "mq_notify",
  "mq_open",
  "mq_timedreceive",
  "mq_timedsend",
  "mq_unlink",
  "mremap",
  "msync",
  "munlock",
  "munlockall",
  "munmap",
  "nanosleep",
  "nfsservctl",
  "nice",
  "oldfstat",
  "oldlstat",
  "oldolduname",
  "oldstat",
  "olduname",
  "open",
  "openat",
  "pause",
  "perf_event_open",
  "personality",
  "pipe",
  "pipe2",
  "pivot_root",
  "poll",
  "ppoll",
  "prctl",
  "pread64",
  "preadv",
  "prof",
  "profil",
  "pselect6",
  "ptrace",
  "putpmsg",
  "pwrite64",
  "pwritev",
  "query_module",
  "quotactl",
  "read",
  "readahead",
  "readdir",
  "readlink",
  "readlinkat",
  "readv",
  "reboot",
  "recvmmsg",
  "remap_file_pages",
  "removexattr",
  "rename",
  "renameat",
  "request_key",
  "restart_syscall",
  "rmdir",
  "rt_sigaction",
  "rt_sigpending",
  "rt_sigprocmask",
  "rt_sigqueueinfo",
  "rt_sigreturn",
  "rt_sigsuspend",
  "rt_sigtimedwait",
  "rt_tgsigqueueinfo",
  "sched_get_priority_max",
  "sched_get_priority_min",
  "sched_getaffinity",
  "sched_getparam",
  "sched_getscheduler",
  "sched_rr_get_interval",
  "sched_setaffinity",
  "sched_setparam",
  "sched_setscheduler",
  "sched_yield",
  "select",
  "sendfile",
  "sendfile64",
  "set_mempolicy",
  "set_robust_list",
  "set_thread_area",
  "set_tid_address",
  "setdomainname",
  "setfsgid",
  "setfsgid32",
  "setfsuid",
  "setfsuid32",
  "setgid",
  "setgid32",
  "setgroups",
  "setgroups32",
  "sethostname",
  "setitimer",
  "setpgid",
  "setpriority",
  "setregid",
  "setregid32",
  "setresgid",
  "setresgid32",
  "setresuid",
  "setresuid32",
  "setreuid",
  "setreuid32",
  "setrlimit",
  "setsid",
  "settimeofday",
  "setuid",
  "setuid32",
  "setxattr",
  "sgetmask",
  "sigaction",
  "sigaltstack",
  "signal",
  "signalfd",
  "signalfd4",
  "sigpending",
  "sigprocmask",
  "sigreturn",
  "sigsuspend",
  "socketcall",
  "splice",
  "ssetmask",
  "stat",
  "stat64",
  "statfs",
  "statfs64",
  "stime",
  "stty",
  "swapoff",
  "swapon",
  "symlink",
  "symlinkat",
  "sync",
  "sync_file_range",
  "sysfs",
  "sysinfo",
  "syslog",
  "tee",
  "tgkill",
  "time",
  "timer_create",
  "timer_delete",
  "timer_getoverrun",
  "timer_gettime",
  "timer_settime",
  "timerfd_create",
  "timerfd_gettime",
  "timerfd_settime",
  "times",
  "tkill",
  "truncate",
  "truncate64",
  "ugetrlimit",
  "ulimit",
  "umask",
  "umount",
  "umount2",
  "uname",
  "unlink",
  "unlinkat",
  "unshare",
  "uselib",
  "ustat",
  "utime",
  "utimensat",
  "utimes",
  "vfork",
  "vhangup",
  "vm86",
  "vm86old",
  "vmsplice",
  "vserver",
  "wait4",
  "waitid",
  "waitpid",
  "write",
  "writev",
  NULL
};

struct token {
	int type;
	char *value;
	int line;
};

struct label {
	char *name;
	int pos;
	int put;
};

struct jlhead *tokens, *labels;

static int addtoken(int type, char *word, int line)
{
	struct token *t;
	t = malloc(sizeof(struct token));
	t->type = type;
	t->value = strdup(word);
	t->line = line;
	return jl_append(tokens, t);
}

#define printinfo( ARGS... ) {snprintf(istr, sizeof(istr), ## ARGS); info(istr);}

static int tokenizer(void *ctx, void (*info)(const char *istr), int (*sgetc)(void *ctx, char *buf))
{
	int n, state=WHITE;
	char buf[2], word[32], istr[256];
	int line=0;
	
	buf[1] = 0;
	word[0] = 0;
	
	while(1) {
		n = sgetc(ctx, buf);
		if(!n) break;
		if(buf[0] == '\n') line++;
		
		switch(state) {
		case WHITE:
			word[0] = 0;
			if(strchr(" \t\n", buf[0]))
				break;
			strcat(word, buf);
			if(buf[0] == '.') {
				state = LABEL;
			} else {
				state = OP;
			}
			break;
		case WHITEOP:
			word[0] = 0;
			if(buf[0] == '\n') {
				state = WHITE;
				break;
			}
			if(strchr(" \t,()", buf[0]))
				break;
			strcat(word, buf);
			if(buf[0] == '"')
				state = STRING;
			else
				state = ARG;
			break;
		case OP:
			if(strchr(" \t\n", buf[0])) {
				printinfo("ERR: tok: %d: missing length modifier", line);
				return -1;
			}
			if(buf[0] == '.') {
				addtoken(OP, word, line);
				state = SIZE;
				break;
			}
			strcat(word, buf);
			break;
		case STRING:
			if(buf[0] == '"') {
				strcat(word, buf);
				addtoken(ARG, word, line);
				state = WHITEOP;
				break;
			}
			strcat(word, buf);
			break;
		case ARG:
			if(buf[0] == '\n') {
				if(strlen(word)) {
					if(word[0] == 'r')
						addtoken(REG, word, line);
					else
						addtoken(ARG, word, line);
				}
				state = WHITE;
				break;
			}
			if(strchr(" \t,()", buf[0])) {
				if(strlen(word)) {
					if(word[0] == 'r')
						addtoken(REG, word, line);
					else
						addtoken(ARG, word, line);
				}
				state = WHITEOP;
				break;
			}
			strcat(word, buf);
			break;
		case SIZE:
			if(strchr("bswl", buf[0])) {
				addtoken(SIZE, buf, line);
				state = WHITEOP;
				break;
			}
			printinfo("ERR: tok: %d: illegal length modifier", line);
			return -1;
			break;
		case LABEL:
			if(strchr(" \t\n", buf[0])) {
				addtoken(LABEL, word, line);
				state = WHITE;
				break;
			}
			strcat(word, buf);
			break;
		}
	}
	return 0;
}

static int parse_op(const char *op)
{
	if(!strcmp(op, "move"))
		return OP_MOVE;
	if(!strcmp(op, "add"))
		return OP_ADD;
	if(!strcmp(op, "sub"))
		return OP_SUB;
	if(!strcmp(op, "lsl"))
		return OP_LSL;
	if(!strcmp(op, "lsr"))
		return OP_LSR;
	if(!strcmp(op, "not"))
		return OP_NOT;
	if(!strcmp(op, "eor"))
		return OP_EOR;
	if(!strcmp(op, "and"))
		return OP_AND;
	if(!strcmp(op, "or"))
		return OP_OR;
	if(!strcmp(op, "store"))
		return OP_STORE;
	if(!strcmp(op, "load"))
		return OP_LOAD;
	if(!strcmp(op, "jmp"))
		return OP_JMP;
	if(!strcmp(op, "jeq"))
		return OP_JEQ;
	if(!strcmp(op, "jne"))
		return OP_JNE;
	if(!strcmp(op, "inc"))
		return OP_INC;
	if(!strcmp(op, "dec"))
		return OP_DEC;
	if(!strcmp(op, "bra"))
		return OP_BRA;
	if(!strcmp(op, "beq"))
		return OP_BEQ;
	if(!strcmp(op, "bne"))
		return OP_BNE;
	if(!strcmp(op, "set"))
		return OP_SET;
	if(!strcmp(op, "addrof"))
		return OP_ADDROF;
	if(!strcmp(op, "syscall"))
		return OP_SYSCALL;
	if(!strcmp(op, "call"))
		return OP_CALL;
	if(!strcmp(op, "errno"))
		return OP_ERRNO;
	if(!strcmp(op, "exit"))
		return OP_EXIT;
	return -1;
}

static uint8_t parse_wordsize(char *value)
{
	if(*value == 'l') return 8;
	if(*value == 'w') return 4;
	if(*value == 's') return 2;
	if(*value == 'b') return 1;
	return 0;
}

static int argcount(struct token *t)
{
	int n = 0;
	while( (t=jl_next(t)) ) {
		if( (t->type != ARG) && (t->type != REG) )
			break;
		n++;
	}
	return n;
}

static uint16_t parse_syscall(const char *value)
{
	int i;
	if(value[0]!='&')
		return -1;

	for(i=0;syscalls[0];i++) {
		if(!strcmp(value+1, syscalls[i]))
			return i;
	}
	return -1;
}

static void put16(void (*oputc)(void *ctx, int pos, uint8_t byte), void *ctx, int *pc, uint16_t value)
{
	oputc(ctx, *pc, (value & 0xff00) >> 8);
	oputc(ctx, (*pc)+1, value & 0xff);
	*pc = *pc + 2;
}

static void put32(void (*oputc)(void *ctx, int pos, uint8_t byte), void *ctx, int *pc, uint32_t value)
{
	oputc(ctx, *pc, (value & 0xff000000) >> 24);
	oputc(ctx, (*pc)+1, (value & 0xff0000) >> 16);
	oputc(ctx, (*pc)+2, (value & 0xff00) >> 8);
	oputc(ctx, (*pc)+3, value & 0xff);
	*pc = *pc + 4;
}

static void put64(void (*oputc)(void *ctx, int pos, uint8_t byte), void *ctx, int *pc, uint64_t value)
{
	oputc(ctx, *pc,     (value & 0xff00000000000000llu) >> 56);
	oputc(ctx, (*pc)+1, (value & 0xff000000000000llu) >> 48);
	oputc(ctx, (*pc)+2, (value & 0xff0000000000llu) >> 40);
	oputc(ctx, (*pc)+3, (value & 0xff00000000llu) >> 32);
	oputc(ctx, (*pc)+4, (value & 0xff000000llu) >> 24);
	oputc(ctx, (*pc)+5, (value & 0xff0000llu) >> 16);
	oputc(ctx, (*pc)+6, (value & 0xff00llu) >> 8);
	oputc(ctx, (*pc)+7,  value & 0xff);
	
	*pc = *pc + 8;
}

static void addlabel(const char *name, int pc)
{
	struct label *l;

	l = malloc(sizeof(struct label));
	l->name = strdup(name);
	l->pos = pc;
	l->put = -1;
	
	jl_ins(labels, l);

	return;
}

static uint32_t labelpos(const char *name, int pos)
{
	struct label *l;

	jl_foreach(labels, l) {
		if(strcmp(l->name, name)==0)
			if(l->pos != -1)
				return l->pos;
	}
	
	/* unresolved label */

	if(pos != -1) {
		l = malloc(sizeof(struct label));
		l->name = strdup(name);
		l->pos = -1;
		l->put = pos;
		
		jl_ins(labels, l);
		return 0;
	}
	
	return -1;
}

static int as(int *len,void (*info)(const char *istr), void (*oputc)(void *ctx, int pos, uint8_t byte), void *ctx)
{
	struct token *t;
	char istr[256];
	int pc = 0, line;
	uint8_t op, wordsize;
	uint16_t src, dst, reg;
	uint32_t offset;
	uint64_t value;
	
	printinfo("INF: assemble %d tokens", tokens->len);
	
	t = jl_head_first(tokens);

	oputc(ctx, pc++, 'J');
	oputc(ctx, pc++, 'E');
	oputc(ctx, pc++, 'L');
	oputc(ctx, pc++, 'V');
	oputc(ctx, pc++, JELVM_MAJOR);
	oputc(ctx, pc++, JELVM_MINOR);

	while(t) {
		line = t->line;
		printinfo("DBG: line %d: %d '%s'", t->line, t->type, t->value);
		if(t->type == LABEL) {
			printinfo("DBG: %d: record label %s at pos %d", t->line, t->value+1, pc);
			addlabel(t->value+1, pc);
			t = jl_next(t);
			continue;
		}
		if(t->type != OP) {
			printinfo("ERR: %d: missing operation", t->line);
			return -1;
		}
		if(!strcmp(t->value, "data")) {
			if( (t = jl_next(t)) == NULL) {
				printinfo("ERR: %d: missing token", line);
				return -1;
			}
			if(t->type != SIZE) {
				printinfo("ERR: %d: missing length modifier", t->line);
				return -1;
			}
			wordsize = parse_wordsize(t->value);
			
			/* read value args and output */
			if(argcount(t) < 1) {
				printinfo("ERR: %d: wrong number of arguments", t->line);
				return -1;
			}
			while(1) {
				t = jl_next(t);
				if(!t) break;
				if(t->type != ARG) break;
				
				if(*t->value == '"') {
					char *p;
					for(p = t->value+1;*p && *p != '\"';p++)
						oputc(ctx, pc++, *p);
					continue;
				}
				if(*t->value == '\'') {
					oputc(ctx, pc++, *(t->value+1));
					continue;
				}
				
				value = strtoull(t->value, NULL, 0);
				printinfo("DBG: %d: value %llx wordsize %d", t->line, value, wordsize);
				switch(wordsize) {
				case 1:
					oputc(ctx, pc++, value);
					break;
				case 2:
					put16(oputc, ctx, &pc, value);
					break;
				case 4:
					put32(oputc, ctx, &pc, value);
					break;
				case 8:
					put64(oputc, ctx, &pc, value);
					break;
				}
			}
			continue;
		}
		op = parse_op(t->value);
		printinfo("INF: %d: op %s: %d", t->line, t->value, op);
		if( (t = jl_next(t)) == NULL) {
			printinfo("ERR: %d: missing token", line);
			return -1;
		}
		if(t->type != SIZE) {
			printinfo("ERR: %d: missing length modifier", t->line);
			return -1;
		}
		wordsize = parse_wordsize(t->value);
		printinfo("DBG: %d: wordsize %s: %d", t->line, t->value, wordsize);
		
		/* fetch args */
		switch(op) {
		case OP_EXIT:
		case OP_ERRNO:
		case OP_BRA:
			if(argcount(t) != 1) {
				printinfo("ERR: %d: wrong number of arguments", t->line);
				return -1;
			}
			t = jl_next(t);
			if(t->type != ARG) { printinfo("ERR: %d: missing arg", t->line); return -1; }
			if(*t->value == '&') {
				value = labelpos(t->value+1, pc+2) - (pc+2);
			} else {
				value = strtoull(t->value, NULL, 0);
			}
			oputc(ctx, pc++, op);
			oputc(ctx, pc++, wordsize);
			put64(oputc, ctx, &pc, value);
			t = jl_next(t);
			continue;
		case OP_MOVE:
		case OP_ADD:
		case OP_SUB:
		case OP_EOR:
		case OP_AND:
		case OP_OR:
		case OP_LSL:
		case OP_LSR:
		case OP_JEQ:
		case OP_JNE:
			if(argcount(t) != 2) {
				printinfo("ERR: %d: wrong number of arguments", t->line);
				return -1;
			}
			t = jl_next(t);
			if(t->type != REG) { printinfo("ERR: %d: missing register", t->line); return -1; }
			src = strtoul(t->value+1, NULL, 0);
			t = jl_next(t);
			if(t->type != REG) { printinfo("ERR: %d: missing register", t->line); return -1; }
			dst = strtoul(t->value+1, NULL, 0);
			oputc(ctx, pc++, op);
			oputc(ctx, pc++, wordsize);
			put16(oputc, ctx, &pc, src);
			put16(oputc, ctx, &pc, dst);
			t = jl_next(t);
			continue;			
		case OP_NOT:
		case OP_JMP:
			if(argcount(t) != 1) {
				printinfo("ERR: %d: wrong number of arguments", t->line);
				return -1;
			}
			t = jl_next(t);
			if(t->type != REG) { printinfo("ERR: %d: missing register", t->line); return -1; }
			reg = strtoul(t->value+1, NULL, 0);
			oputc(ctx, pc++, op);
			oputc(ctx, pc++, wordsize);
			put16(oputc, ctx, &pc, reg);
			t = jl_next(t);
			continue;
		case OP_SET:
		case OP_INC:
		case OP_DEC:
		case OP_BEQ:
		case OP_BNE:
			if(argcount(t) != 2) {
				printinfo("ERR: %d: wrong number of arguments", t->line);
				return -1;
			}
			t = jl_next(t);
			if(t->type != REG) { printinfo("ERR: %d: missing register", t->line); return -1; }
			reg = strtoul(t->value+1, NULL, 0);

			t = jl_next(t);
			if(t->type != ARG) { printinfo("ERR: %d: missing arg", t->line); return -1; }
			if(*t->value == '&') {
				value = labelpos(t->value+1, pc+4) - (pc+4);
			} else {
				value = strtoull(t->value, NULL, 0);
			}
			printinfo("DBG: value  %s: %llu", t->value, value);
			oputc(ctx, pc++, op);
			oputc(ctx, pc++, wordsize);
			put16(oputc, ctx, &pc, reg);
			put64(oputc, ctx, &pc, value);

			t = jl_next(t);
			continue;
		case OP_ADDROF:
			if(argcount(t) != 2) {
				printinfo("ERR: %d: wrong number of arguments", t->line);
				return -1;
			}
			t = jl_next(t);
			if(t->type != ARG) { printinfo("ERR: %d: missing arg", t->line); return -1; }
			if(*t->value == '&') {
				offset = labelpos(t->value+1, pc+4) - (pc+4);
			} else {
				offset = strtoull(t->value, NULL, 0);
			}
			t = jl_next(t);
			
			if(t->type != REG) { printinfo("ERR: %d: missing reg", t->line); return -1; }
			reg = atoi(t->value+1);
			printinfo("DBG: offset  %s: %d", t->value, offset);
			oputc(ctx, pc++, op);
			oputc(ctx, pc++, wordsize);
			put16(oputc, ctx, &pc, reg);
			put64(oputc, ctx, &pc, offset);

			t = jl_next(t);
			continue;			
		case OP_STORE:
			if(argcount(t) != 3) {
				printinfo("ERR: %d: wrong number of arguments", t->line);
				return -1;
			}
			t = jl_next(t);
			if(t->type != REG) { printinfo("ERR: %d: missing reg", t->line); return -1; }
			src = atoi(t->value+1);

			t = jl_next(t);
			if(t->type != ARG) { printinfo("ERR: %d: missing arg", t->line); return -1; }
			offset = atoi(t->value);
			printinfo("DBG: offset  %s: %d\n", t->value, offset);

			t = jl_next(t);
			if(t->type != REG) { printinfo("ERR: %d: missing reg", t->line); return -1; }
			dst = atoi(t->value+1);

			oputc(ctx, pc++, op);
			oputc(ctx, pc++, wordsize);
			put16(oputc, ctx, &pc, src);
			put16(oputc, ctx, &pc, dst);
			put32(oputc, ctx, &pc, offset);

			t = jl_next(t);
			continue;
		case OP_LOAD:
			if(argcount(t) != 3) {
				printinfo("ERR: %d: wrong number of arguments", t->line);
				return -1;
			}
			t = jl_next(t);
			if(t->type != ARG) { printinfo("ERR: %d: missing arg", t->line); return -1; }
			offset = atoi(t->value);
			printinfo("DBG: offset  %s: %d\n", t->value, offset);

			t = jl_next(t);
			if(t->type != REG) { printinfo("ERR: %d: missing reg", t->line); return -1; }
			src = atoi(t->value+1);

			t = jl_next(t);
			if(t->type != REG) { printinfo("ERR: %d: missing reg", t->line); return -1; }
			dst = atoi(t->value+1);

			oputc(ctx, pc++, op);
			oputc(ctx, pc++, wordsize);
			put16(oputc, ctx, &pc, src);
			put16(oputc, ctx, &pc, dst);
			put32(oputc, ctx, &pc, offset);

			t = jl_next(t);
			continue;
		case OP_SYSCALL:
			if(argcount(t) != 1) {
				printinfo("ERR: %d: wrong number of arguments", t->line);
				return -1;
			}
			t = jl_next(t);
			if(t->type != ARG) { printinfo("ERR: %d: missing arg", t->line); return -1; }
			value = parse_syscall(t->value);
			if(value == -1)  { printinfo("ERR: %d: not a syscall", t->line); return -1; }
			oputc(ctx, pc++, op);
			oputc(ctx, pc++, wordsize);
			put16(oputc, ctx, &pc, value);

			t = jl_next(t);
			continue;
		case OP_CALL:
			if(argcount(t) != 1) {
				printinfo("ERR: %d: wrong number of arguments", t->line);
				return -1;
			}
			t = jl_next(t);
			if(t->type != REG) { printinfo("ERR: %d: missing reg", t->line); return -1; }
			dst = atoi(t->value+1);
			oputc(ctx, pc++, op);
			oputc(ctx, pc++, wordsize);
			put16(oputc, ctx, &pc, dst);

			t = jl_next(t);
			continue;
		}
	}
	*len = pc;

	/* resolve any remaining labels */
	{
		struct label *l;
		int n, pos;
		
		jl_foreach(labels, l) {
			if(l->pos == -1) {
				pos = labelpos(l->name, -1);
				if(pos == -1) {
					printinfo("ERR: failed to resolve label %s",
						l->name);
					return -1;
				}
				n = l->put;
				printinfo("DBG: put delta for addr %d for label %s in %d", pos, l->name, n);
				put64(oputc, ctx, &n, pos - n);
			}
		}
	}
	return 0;
}

static void token_free(void *item)
{
	struct token *t = item;
	free(t->value);
	free(t);
}

static void label_free(void *item)
{
	struct label *l = item;
	free(l->name);
	free(l);
}

int jelvm_as(int *len, void (*info)(const char *istr), int (*sgetc)(void *ctx, char *buf), void (*putc)(void *ctx, int pos, uint8_t byte), void *ctx)
{
	int rc=0;
	
	tokens = jl_new(); 
	labels = jl_new(); 

	rc = tokenizer(ctx, info, sgetc);
	if(rc == 0)
		rc = as(len, info, putc, ctx);
	
	/* FIXME: dealloc lists and contents */
	jl_freefn(tokens, token_free);
	jl_freefn(labels, label_free);

	return rc;
}
