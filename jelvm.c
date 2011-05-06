/*
 * File: jelvm.c
 * Implements:
 *
 * Copyright: Jens Låås, 2011
 * Copyright license: According to GPL, see file COPYING in this directory.
 *
 */
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stddef.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <poll.h>
#include <sys/signalfd.h>
#include <signal.h>
#include <time.h>
#include <sys/sendfile.h>

#include "jelvm.h"

static int jelvm_exec_regs(uint64_t *regs, void *code, uint64_t *iv, int ivlen, unsigned int flags, void (*info)(const char *istr));

#define ntohll(x) (((uint64_t)(ntohl((int)((x << 32) >> 32))) << 32) | (unsigned int)ntohl(((int)(x >> 32)))) //By Runner
#define htonll(x) ntohll(x)

static void *ptr(uint64_t p)
{
	if(sizeof(void *) == 4) return (void*)(uint32_t) p;
	return (void*) p;
}

static uint64_t ptoull(void *p)
{
	if(sizeof(void *) == 4) return (uint64_t)(uint32_t) p;
	return (uint64_t) p;
}

struct vm_sighandler {
	void *code;
	uint64_t *regs;
};

static struct vm_sighandler sighandlers[32];

static void jelvm_sighandler(int signum, siginfo_t *info , void *ucontext_t)
{
	uint64_t iv[2];
	iv[0] = signum;
	iv[1] = ptoull(info);
	jelvm_exec_regs(sighandlers[signum].regs, sighandlers[signum].code, iv, 2, 0, NULL);
	return;
}

static int jelvm_sigaction(uint64_t *regs,
			   int signum,
			   void *vm_sigaction,
			   sigset_t *vm_mask,
			   int sa_flags,
			   uint64_t *sa_oldsigaction)
{
	struct sigaction act;
	int rc;
	
	if(vm_sigaction == 0) {
	        *sa_oldsigaction = ptoull(sighandlers[signum].code);
		return 0;
	}
	
	act.sa_sigaction = jelvm_sighandler;
	memcpy(&act.sa_mask, vm_mask, sizeof(sigset_t));
	act.sa_flags = sa_flags;
	if((rc=sigaction(signum, &act, NULL))==0) {
	        if(sa_oldsigaction) *sa_oldsigaction = ptoull(sighandlers[signum].code);
		sighandlers[signum].code = vm_sigaction;
		sighandlers[signum].regs = regs;
	}
	return rc;
}

static uint64_t regclr(uint64_t *regs, int reg, int wordsize)
{
	switch(wordsize) {
	case 1:
		return regs[reg] & 0xffffffffffffff00llu;
	case 2:
		return regs[reg] & 0xffffffffffff0000llu;
	case 4:
		return regs[reg] & 0xffffffff00000000llu;
	}
	return 0;
}

static uint64_t regmask(uint64_t *regs, int reg, int wordsize)
{
	switch(wordsize) {
	case 1:
		return regs[reg] & 0xffllu;
	case 2:
		return regs[reg] & 0xffffllu;
	case 4:
		return regs[reg] & 0xffffffffllu;
	}
	return regs[reg];
}

static uint64_t bitmask(uint64_t val, int wordsize)
{
	switch(wordsize) {
	case 1:
		return val & 0xffllu;
	case 2:
		return val & 0xffffllu;
	case 4:
		return val & 0xffffffffllu;
	}
	return val;
}

uint16_t get16(uint8_t **pc)
{
	uint16_t v;
	v = ntohs(*((uint16_t *)*pc));
	(*pc)+=2;
	return v;
}
uint32_t get32(uint8_t **pc)
{
	uint32_t v;
	v = ntohl(*((uint32_t *)*pc));
	(*pc)+=4;
	return v;
}
uint64_t get64(uint8_t **pc)
{
	uint64_t v;
	v = ntohll(*((uint64_t *)*pc));
	(*pc)+=8;
	return v;
}

#define printinfo( ARGS... ) {snprintf(istr, sizeof(istr), ## ARGS); info(istr);}

static int jelvm_exec_regs(uint64_t *regs, void *code, uint64_t *iv, int ivlen, unsigned int flags, void (*info)(const char *istr))
{
	int j;
	uint8_t *pc;
	char istr[512];
	uint8_t op, wordsize;
	uint16_t reg, src, dst, sys;
	uint32_t offset;
	uint64_t value;
	uint64_t (*fn)(uint64_t *regs);

	if(flags & JELVM_DEBUG) printinfo("INF:iv %p len %d", iv, ivlen);
	if(flags & JELVM_DEBUG) printinfo("INF:exec begin at %p", code);
	
	for(j=0;j<ivlen;j++)
		regs[j] = iv[j];
	
	pc = code;
	
	if(memcmp(code, "JELV", 4)) {
		if(flags & JELVM_TRACE) printinfo("ERR:not a supported vm");
		return -1;
	}
	pc += 6;
	
	while(1) {
		op = *pc++;
		if(flags & JELVM_TRACE) printinfo("TRC:pc=%p op 0x%x: ", pc, op);
		switch(op) {
		case OP_MOVE:
			wordsize = *pc++;
			src = get16(&pc);
			dst = get16(&pc);
			regs[dst] = regclr(regs, dst, wordsize) + regmask(regs, src, wordsize);
			continue;
		case OP_ADD:
			wordsize = *pc++;
			src = get16(&pc);
			dst = get16(&pc);
			regs[dst] = regclr(regs, dst, wordsize) + bitmask(regmask(regs, src, wordsize) +
									  regmask(regs, dst, wordsize), wordsize);
			continue;
		case OP_SUB:
			wordsize = *pc++;
			src = get16(&pc);
			dst = get16(&pc);
			regs[dst] = regclr(regs, dst, wordsize) + bitmask(regmask(regs, dst, wordsize) -
									  regmask(regs, src, wordsize), wordsize);
			continue;
		case OP_LSL:
			wordsize = *pc++;
			reg = get16(&pc);
			value = get16(&pc);
			regs[reg] = regclr(regs, reg, wordsize) + bitmask(regmask(regs, reg, wordsize) << value, wordsize);
			continue;
		case OP_LSR:
			wordsize = *pc++;
			reg = get16(&pc);
			value = get16(&pc);
			regs[reg] = regclr(regs, reg, wordsize) + bitmask(regmask(regs, reg, wordsize) >> value, wordsize);
			continue;
		case OP_NOT:
			wordsize = *pc++;
			reg = get16(&pc);
			regs[reg] = regclr(regs, reg, wordsize) + bitmask(!regmask(regs, reg, wordsize), wordsize);
			continue;
		case OP_EOR:
			wordsize = *pc++;
			src = get16(&pc);
			dst = get16(&pc);
			regs[dst] = regclr(regs, dst, wordsize) + bitmask(regmask(regs, dst, wordsize) ^
									  regmask(regs, src, wordsize), wordsize);
			continue;
		case OP_AND:
			wordsize = *pc++;
			src = get16(&pc);
			dst = get16(&pc);
			regs[dst] = regclr(regs, dst, wordsize) + bitmask(regmask(regs, dst, wordsize) &
									  regmask(regs, src, wordsize), wordsize);
			continue;
		case OP_OR:
			wordsize = *pc++;
			src = get16(&pc);
			dst = get16(&pc);
			regs[dst] = regclr(regs, dst, wordsize) + bitmask(regmask(regs, dst, wordsize) |
									  regmask(regs, src, wordsize), wordsize);
			continue;
		case OP_LOAD:
			wordsize = *pc++;
			src = get16(&pc);
			dst = get16(&pc);
			offset = get32(&pc);

			if(flags & JELVM_TRACE)  printinfo("DBG:load %u(%u),%u",
							   offset, src,
							   dst);

			switch(wordsize) {
			case 1:
				regs[dst] = regclr(regs, dst, wordsize) +
					*((uint8_t*)ptr(regs[src]+offset));
				break;
			case 2:
				regs[dst] = regclr(regs, dst, wordsize) +
					*((uint16_t*)ptr(regs[src]+offset));
				break;
			case 4:
				regs[dst] = regclr(regs, dst, wordsize) +
					*((uint32_t*)ptr(regs[src]+offset));
				break;
			case 8:
				regs[dst] = *((uint64_t*)ptr(regs[src]+offset));
				break;
			}
			continue;
		case OP_JMP:
			wordsize = *pc++;
			reg = get16(&pc);
			pc = ptr(regs[reg]);
			continue;
		case OP_JEQ:
			wordsize = *pc++;
			src = get16(&pc);
			dst = get16(&pc);
			if(regmask(regs, src, wordsize)==0) {
				pc = ptr(regs[dst]);
			}
			continue;
		case OP_JNE:
			wordsize = *pc++;
			src = get16(&pc);
			dst = get16(&pc);
			if(regmask(regs, src, wordsize)) {
				pc = ptr(regs[dst]);
			}
			continue;
		case OP_BRA:
			pc++;
			value = get64(&pc);
			if(flags & JELVM_TRACE)  printinfo("DBG:bra %p + %llu => %p",
							   pc - 8, value,
							   pc - 8 + value);
			pc = pc + value - 8;
			continue;
		case OP_ERRNO:
			pc++;
			value = get64(&pc);
			errno = value;
			continue;
		case OP_BEQ:
			wordsize = *pc++;
			reg = get16(&pc);
			value = get64(&pc);
			if(regmask(regs, reg, wordsize)==0) {
				pc = pc + value;
			}
			continue;
		case OP_BNE:
			wordsize = *pc++;
			reg = get16(&pc);
			value = get64(&pc);
			if(regmask(regs, reg, wordsize)) {
				pc = pc + value;
			}
			continue;
		case OP_EXIT:
			pc++;
			value = get64(&pc);
			if(flags & JELVM_TRACE) printinfo("TRC:exit %llx", value);
			return value;
		case OP_INC:
			wordsize = *pc++;
			reg = get16(&pc);
			value = get64(&pc);
			regs[reg] =
				regclr(regs, reg, wordsize) +
				bitmask(regmask(regs, reg, wordsize) +
					bitmask(value, wordsize),
					wordsize);
			continue;
		case OP_DEC:
			wordsize = *pc++;
			reg = get16(&pc);
			value = get64(&pc);
			regs[reg] =
				regclr(regs, reg, wordsize) +
				bitmask(regmask(regs, reg, wordsize) -
					bitmask(value, wordsize),
					wordsize);
			continue;
		case OP_STORE:
			wordsize = *pc++;
			src = get16(&pc);
			dst = get16(&pc);
			offset = get32(&pc);

			if(flags & JELVM_TRACE)  printinfo("DBG:store %u, %u(%u)",
							   src, offset,
							   dst);

			switch(wordsize) {
			case 1:
				*((uint8_t*)ptr(regs[dst]+offset))=
					regmask(regs, src, wordsize);
				break;
			case 2:
				*((uint16_t*)ptr(regs[dst]+offset))=
					regmask(regs, src, wordsize);
				break;
			case 4:
				*((uint32_t*)ptr(regs[dst]+offset))=
					regmask(regs, src, wordsize);
				break;
			case 8:
				*((uint64_t*)ptr(regs[dst]+offset))=
					regmask(regs, src, wordsize);
				break;
			}
			continue;
		case OP_ADDROF:
			wordsize = *pc++;
			reg = get16(&pc);
			value = get64(&pc);
			if(flags & JELVM_TRACE)  printinfo("DBG:addrof %u = %p + %llx", reg, pc , value);
			regs[reg] = ptoull(pc) + (int64_t) value - 8;
			continue;
		case OP_SET:
			wordsize = *pc++;
			reg = get16(&pc);
			value = get64(&pc);
			if(flags & JELVM_TRACE) printinfo("DBG:set r%d, 0x%llx", reg, value);
			regs[reg] =
				regclr(regs, reg, wordsize) +
				bitmask(value, wordsize);
			continue;
		case OP_CALL:
			wordsize = *pc++;
			reg = get16(&pc);
			if(flags & JELVM_TRACE)  printinfo("TRC:call %llu", regs[reg]);
			fn = ptr(regs[reg]);
			regs[0] = fn(regs);
			continue;
		case OP_SYSCALL:
			wordsize = *pc++;
			sys = get16(&pc);
			if(flags & JELVM_TRACE) printinfo("TRC:syscall %x ", sys);
			switch(sys) {
			case SYSCALL_chdir:
				regs[0] = chdir(ptr(regs[2]));
				regs[1] = errno;
				break;
			case SYSCALL_close:
				regs[0] = close(regs[2]);
				regs[1] = errno;
				break;
			case SYSCALL_execve:
				regs[0] = execve(ptr(regs[2]),
						 ptr(regs[3]),
						 ptr(regs[4]));
				regs[1] = errno;
				break;
			case SYSCALL_fchdir:
				regs[0] = fchdir(regs[2]);
				regs[1] = errno;
				break;
			case SYSCALL_fork:
				regs[0] = fork();
				regs[1] = errno;
				break;
			case SYSCALL_getpid:
				regs[0] = getpid();
				regs[1] = errno;
				if(flags & JELVM_TRACE) printinfo("DBG:rc=%llu errno=%llu : %s", regs[0], regs[1], strerror(regs[1]));
				break;
			case SYSCALL_gettimeofday:
				regs[0] = gettimeofday(ptr(regs[2]),
						       ptr(regs[3]));
				regs[1] = errno;
				break;
			case SYSCALL_settimeofday:
				regs[0] = settimeofday(ptr(regs[2]),
						       ptr(regs[3]));
				regs[1] = errno;
				break;
			case SYSCALL_waitpid:
				regs[0] = waitpid(regs[2], ptr(regs[3]), regs[4]);
				regs[1] = errno;
				break;
			case SYSCALL_write:
				if(flags & JELVM_TRACE) printinfo("DBG:write(%llu, %llx, %llu) ",
							       regs[2], regs[3], regs[4]);
				regs[0] = write(regs[2], ptr(regs[3]), regs[4]);
				regs[1] = errno;
				if(flags & JELVM_TRACE) printinfo("DBG:rc=%llu errno=%llu : %s", regs[0], regs[1], strerror(regs[1]));
				break;
			case SYSCALL_open:
				regs[0] = open(ptr(regs[2]), regs[3], regs[4]);
				regs[1] = errno;
				break;
			case SYSCALL_munmap:
				regs[0] = munmap(ptr(regs[2]), regs[3]);
				break;
			case SYSCALL_mmap:
				if(flags & JELVM_TRACE) printinfo("DBG: mmap(%llu, %llu, %llu, %llu, "
							       "%llu, %llu, %llu, %llu) ",
							       regs[0], regs[1], regs[2], regs[3],
							       regs[4], regs[5], regs[6], regs[7]);
				regs[0] = ptoull(mmap(ptr(regs[2]), regs[3], 
						      regs[4], regs[5],
						      regs[6], regs[7]));
				regs[1] = errno;
				if(flags & JELVM_TRACE) printinfo("DBG:rc=%llu errno=%llu : %s", regs[0], regs[1], strerror(regs[1]));
				break;
			case SYSCALL_nanosleep:
				regs[0] = nanosleep(ptr(regs[2]), ptr(regs[2]));
				regs[1] = errno;
				break;
			case SYSCALL_pipe:
				regs[0] = pipe(ptr(regs[2]));
				regs[1] = errno;
				break;
			case SYSCALL_pipe2:
				regs[0] = pipe2(ptr(regs[2]), regs[3]);
				regs[1] = errno;
				break;
			case SYSCALL_poll:
				regs[0] = poll(ptr(regs[2]), regs[3], regs[4]);
				regs[1] = errno;
				break;
			case SYSCALL_read:
				regs[0] = read(regs[2], ptr(regs[3]), regs[4]);
				regs[1] = errno;
				break;
			case SYSCALL_sendfile:
				regs[0] = sendfile(regs[2], regs[3], ptr(regs[4]), regs[5]);
				regs[1] = errno;
				break;
			case SYSCALL_setsid:
				regs[0] = setsid();
				regs[1] = errno;
                                break;
			case SYSCALL_sigaction:
				regs[0] = jelvm_sigaction(regs,
							  regs[2],
							  ptr(regs[3]),
							  ptr(regs[4]),
							  regs[5],
							  ptr(regs[6]));
				regs[1] = errno;
				break;
			case SYSCALL_signalfd:
				regs[0] = signalfd(regs[2], ptr(regs[3]), regs[4]);
				regs[1] = errno;
				break;
			case SYSCALL_sigpending:
				regs[0] = sigpending(ptr(regs[2]));
				regs[1] = errno;
				break;
			case SYSCALL_sigprocmask:
				regs[0] = sigprocmask(regs[2], ptr(regs[3]), ptr(regs[4]));
				regs[1] = errno;
				break;
			case SYSCALL_sleep:
				regs[0] = sleep(regs[2]);
				regs[1] = errno;
				break;
			case SYSCALL_socket:
				regs[0] = socket(regs[2], regs[3], regs[4]);
				regs[1] = errno;
				break;
			case SYSCALL_accept:
				regs[0] = accept(regs[2], ptr(regs[3]), ptr(regs[4]));
				regs[1] = errno;
				break;
			case SYSCALL_bind:
				regs[0] = bind(regs[2], ptr(regs[3]),regs[4]);
				regs[1] = errno;
				break;
			case SYSCALL_listen:
				regs[0] = listen(regs[2], regs[3]);
				regs[1] = errno;
				break;
			case SYSCALL_connect:
				regs[0] = connect(regs[2], ptr(regs[3]), regs[4]);
				regs[1] = errno;
				break;
			}
			continue;
		}
		if(flags & JELVM_TRACE) printinfo("ERR:unknown instruction");
		return -1;
	}
	

	return -1;
}

int jelvm_exec(void *code, uint64_t *iv, int ivlen, unsigned int flags, void (*info)(const char *istr))
{
	uint64_t regs[4096];
	return jelvm_exec_regs(regs, code, iv, ivlen, flags,  info);
}
