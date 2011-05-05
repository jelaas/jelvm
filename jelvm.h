#ifndef JELVM_H
#define JELVM_H

#include <stdint.h>

#define JELVM_DEBUG 1
#define JELVM_INFO 2
#define JELVM_TRACE 4
#define JELVM_WARN 8
#define JELVM_ERROR 16

#define OP_EXIT 0

/* register direct 

OP_MOVE reg -> reg

OP_ADD reg+reg -> reg
OP_SUB reg-reg -> reg
OP_LSL reg << data -> reg
OP_LSR reg >> data -> reg
OP_NOT !reg -> reg
OP_EOR reg ^ reg -> reg
OP_AND reg & reg -> reg
OP_OR reg | reg -> reg
*/

#define OP_MOVE 0x10
#define OP_ADD 0x11
#define OP_SUB 0x12
#define OP_LSL 0x13
#define OP_LSR 0x14
#define OP_NOT 0x15
#define OP_EOR 0x16
#define OP_AND 0x17
#define OP_OR 0x18

/* register indirect

OP_STORE reg -> *(reg+offset)    store.W rN,V(rN)
OP_LOAD *(reg+offset) -> reg

OP_JMP reg -> pc
OP_JEQ [reg] reg -> pc
OP_JNE [reg] reg -> pc
 */

#define OP_STORE 0x30
#define OP_LOAD 0x31
#define OP_JMP 0x32
#define OP_JEQ 0x33
#define OP_JNE 0x34


/* immediate

OP_ADDROF pc+data -> reg    addrof.l rN,V
                            addrof.l rN,&LABEL

OP_SET data -> reg          set.W rN V

OP_INC reg+data -> reg
OP_DEC reg-data -> reg

OP_BRA pc+data -> pc
OP_BEQ [reg] pc+data -> pc
OP_BNE [reg] pc+data -> pc
 */

#define OP_ADDROF 0x50
#define OP_SET 0x51
#define OP_INC 0x52
#define OP_DEC 0x53
#define OP_BRA 0x54
#define OP_BEQ 0x55
#define OP_BNE 0x56


/* external

OP_SYSCALL syscall reg[] -> reg[0], reg[1]     syscall.s &SYSCALL

  Make a C function call: reg[0] = fn(&regs)
  OP_CALL *(reg) reg[] -> reg[0], reg[1]
 */

#define OP_SYSCALL 0x70
#define OP_CALL 0x71
#define OP_ERRNO 0x72

enum {
  SYSCALL__llseek,
  SYSCALL__newselect,
  SYSCALL__sysctl,
  SYSCALL_access,
  SYSCALL_acct,
  SYSCALL_add_key,
  SYSCALL_adjtimex,
  SYSCALL_afs_syscall,
  SYSCALL_alarm,
  SYSCALL_bdflush,
  SYSCALL_break,
  SYSCALL_brk,
  SYSCALL_capget,
  SYSCALL_capset,
  SYSCALL_chdir,
  SYSCALL_chmod,
  SYSCALL_chown,
  SYSCALL_chown32,
  SYSCALL_chroot,
  SYSCALL_clock_getres,
  SYSCALL_clock_gettime,
  SYSCALL_clock_nanosleep,
  SYSCALL_clock_settime,
  SYSCALL_clone,
  SYSCALL_close,
  SYSCALL_creat,
  SYSCALL_create_module,
  SYSCALL_delete_module,
  SYSCALL_dup,
  SYSCALL_dup2,
  SYSCALL_dup3,
  SYSCALL_epoll_create,
  SYSCALL_epoll_create1,
  SYSCALL_epoll_ctl,
  SYSCALL_epoll_pwait,
  SYSCALL_epoll_wait,
  SYSCALL_eventfd,
  SYSCALL_eventfd2,
  SYSCALL_execve,
  SYSCALL_exit,
  SYSCALL_exit_group,
  SYSCALL_faccessat,
  SYSCALL_fadvise64,
  SYSCALL_fadvise64_64,
  SYSCALL_fallocate,
  SYSCALL_fchdir,
  SYSCALL_fchmod,
  SYSCALL_fchmodat,
  SYSCALL_fchown,
  SYSCALL_fchown32,
  SYSCALL_fchownat,
  SYSCALL_fcntl,
  SYSCALL_fcntl64,
  SYSCALL_fdatasync,
  SYSCALL_fgetxattr,
  SYSCALL_flistxattr,
  SYSCALL_flock,
  SYSCALL_fork,
  SYSCALL_fremovexattr,
  SYSCALL_fsetxattr,
  SYSCALL_fstat,
  SYSCALL_fstat64,
  SYSCALL_fstatat64,
  SYSCALL_fstatfs,
  SYSCALL_fstatfs64,
  SYSCALL_fsync,
  SYSCALL_ftime,
  SYSCALL_ftruncate,
  SYSCALL_ftruncate64,
  SYSCALL_futex,
  SYSCALL_futimesat,
  SYSCALL_get_kernel_syms,
  SYSCALL_get_mempolicy,
  SYSCALL_get_robust_list,
  SYSCALL_get_thread_area,
  SYSCALL_getcpu,
  SYSCALL_getcwd,
  SYSCALL_getdents,
  SYSCALL_getdents64,
  SYSCALL_getegid,
  SYSCALL_getegid32,
  SYSCALL_geteuid,
  SYSCALL_geteuid32,
  SYSCALL_getgid,
  SYSCALL_getgid32,
  SYSCALL_getgroups,
  SYSCALL_getgroups32,
  SYSCALL_getitimer,
  SYSCALL_getpgid,
  SYSCALL_getpgrp,
  SYSCALL_getpid,
  SYSCALL_getpmsg,
  SYSCALL_getppid,
  SYSCALL_getpriority,
  SYSCALL_getresgid,
  SYSCALL_getresgid32,
  SYSCALL_getresuid,
  SYSCALL_getresuid32,
  SYSCALL_getrlimit,
  SYSCALL_getrusage,
  SYSCALL_getsid,
  SYSCALL_gettid,
  SYSCALL_gettimeofday,
  SYSCALL_getuid,
  SYSCALL_getuid32,
  SYSCALL_getxattr,
  SYSCALL_gtty,
  SYSCALL_idle,
  SYSCALL_init_module,
  SYSCALL_inotify_add_watch,
  SYSCALL_inotify_init,
  SYSCALL_inotify_init1,
  SYSCALL_inotify_rm_watch,
  SYSCALL_io_cancel,
  SYSCALL_io_destroy,
  SYSCALL_io_getevents,
  SYSCALL_io_setup,
  SYSCALL_io_submit,
  SYSCALL_ioctl,
  SYSCALL_ioperm,
  SYSCALL_iopl,
  SYSCALL_ioprio_get,
  SYSCALL_ioprio_set,
  SYSCALL_ipc,
  SYSCALL_kexec_load,
  SYSCALL_keyctl,
  SYSCALL_kill,
  SYSCALL_lchown,
  SYSCALL_lchown32,
  SYSCALL_lgetxattr,
  SYSCALL_link,
  SYSCALL_linkat,
  SYSCALL_listxattr,
  SYSCALL_llistxattr,
  SYSCALL_lock,
  SYSCALL_lookup_dcookie,
  SYSCALL_lremovexattr,
  SYSCALL_lseek,
  SYSCALL_lsetxattr,
  SYSCALL_lstat,
  SYSCALL_lstat64,
  SYSCALL_madvise,
  SYSCALL_madvise1,
  SYSCALL_mbind,
  SYSCALL_migrate_pages,
  SYSCALL_mincore,
  SYSCALL_mkdir,
  SYSCALL_mkdirat,
  SYSCALL_mknod,
  SYSCALL_mknodat,
  SYSCALL_mlock,
  SYSCALL_mlockall,
  SYSCALL_mmap,
  SYSCALL_mmap2,
  SYSCALL_modify_ldt,
  SYSCALL_mount,
  SYSCALL_move_pages,
  SYSCALL_mprotect,
  SYSCALL_mpx,
  SYSCALL_mq_getsetattr,
  SYSCALL_mq_notify,
  SYSCALL_mq_open,
  SYSCALL_mq_timedreceive,
  SYSCALL_mq_timedsend,
  SYSCALL_mq_unlink,
  SYSCALL_mremap,
  SYSCALL_msync,
  SYSCALL_munlock,
  SYSCALL_munlockall,
  SYSCALL_munmap,
  SYSCALL_nanosleep,
  SYSCALL_nfsservctl,
  SYSCALL_nice,
  SYSCALL_oldfstat,
  SYSCALL_oldlstat,
  SYSCALL_oldolduname,
  SYSCALL_oldstat,
  SYSCALL_olduname,
  SYSCALL_open,
  SYSCALL_openat,
  SYSCALL_pause,
  SYSCALL_perf_event_open,
  SYSCALL_personality,
  SYSCALL_pipe,
  SYSCALL_pipe2,
  SYSCALL_pivot_root,
  SYSCALL_poll,
  SYSCALL_ppoll,
  SYSCALL_prctl,
  SYSCALL_pread64,
  SYSCALL_preadv,
  SYSCALL_prof,
  SYSCALL_profil,
  SYSCALL_pselect6,
  SYSCALL_ptrace,
  SYSCALL_putpmsg,
  SYSCALL_pwrite64,
  SYSCALL_pwritev,
  SYSCALL_query_module,
  SYSCALL_quotactl,
  SYSCALL_read,
  SYSCALL_readahead,
  SYSCALL_readdir,
  SYSCALL_readlink,
  SYSCALL_readlinkat,
  SYSCALL_readv,
  SYSCALL_reboot,
  SYSCALL_recvmmsg,
  SYSCALL_remap_file_pages,
  SYSCALL_removexattr,
  SYSCALL_rename,
  SYSCALL_renameat,
  SYSCALL_request_key,
  SYSCALL_restart_syscall,
  SYSCALL_rmdir,
  SYSCALL_rt_sigaction,
  SYSCALL_rt_sigpending,
  SYSCALL_rt_sigprocmask,
  SYSCALL_rt_sigqueueinfo,
  SYSCALL_rt_sigreturn,
  SYSCALL_rt_sigsuspend,
  SYSCALL_rt_sigtimedwait,
  SYSCALL_rt_tgsigqueueinfo,
  SYSCALL_sched_get_priority_max,
  SYSCALL_sched_get_priority_min,
  SYSCALL_sched_getaffinity,
  SYSCALL_sched_getparam,
  SYSCALL_sched_getscheduler,
  SYSCALL_sched_rr_get_interval,
  SYSCALL_sched_setaffinity,
  SYSCALL_sched_setparam,
  SYSCALL_sched_setscheduler,
  SYSCALL_sched_yield,
  SYSCALL_select,
  SYSCALL_sendfile,
  SYSCALL_sendfile64,
  SYSCALL_set_mempolicy,
  SYSCALL_set_robust_list,
  SYSCALL_set_thread_area,
  SYSCALL_set_tid_address,
  SYSCALL_setdomainname,
  SYSCALL_setfsgid,
  SYSCALL_setfsgid32,
  SYSCALL_setfsuid,
  SYSCALL_setfsuid32,
  SYSCALL_setgid,
  SYSCALL_setgid32,
  SYSCALL_setgroups,
  SYSCALL_setgroups32,
  SYSCALL_sethostname,
  SYSCALL_setitimer,
  SYSCALL_setpgid,
  SYSCALL_setpriority,
  SYSCALL_setregid,
  SYSCALL_setregid32,
  SYSCALL_setresgid,
  SYSCALL_setresgid32,
  SYSCALL_setresuid,
  SYSCALL_setresuid32,
  SYSCALL_setreuid,
  SYSCALL_setreuid32,
  SYSCALL_setrlimit,
  SYSCALL_setsid,
  SYSCALL_settimeofday,
  SYSCALL_setuid,
  SYSCALL_setuid32,
  SYSCALL_setxattr,
  SYSCALL_sgetmask,
  SYSCALL_sigaction,
  SYSCALL_sigaltstack,
  SYSCALL_signal,
  SYSCALL_signalfd,
  SYSCALL_signalfd4,
  SYSCALL_sigpending,
  SYSCALL_sigprocmask,
  SYSCALL_sigreturn,
  SYSCALL_sigsuspend,
  SYSCALL_socketcall,
  SYSCALL_splice,
  SYSCALL_ssetmask,
  SYSCALL_stat,
  SYSCALL_stat64,
  SYSCALL_statfs,
  SYSCALL_statfs64,
  SYSCALL_stime,
  SYSCALL_stty,
  SYSCALL_swapoff,
  SYSCALL_swapon,
  SYSCALL_symlink,
  SYSCALL_symlinkat,
  SYSCALL_sync,
  SYSCALL_sync_file_range,
  SYSCALL_sysfs,
  SYSCALL_sysinfo,
  SYSCALL_syslog,
  SYSCALL_tee,
  SYSCALL_tgkill,
  SYSCALL_time,
  SYSCALL_timer_create,
  SYSCALL_timer_delete,
  SYSCALL_timer_getoverrun,
  SYSCALL_timer_gettime,
  SYSCALL_timer_settime,
  SYSCALL_timerfd_create,
  SYSCALL_timerfd_gettime,
  SYSCALL_timerfd_settime,
  SYSCALL_times,
  SYSCALL_tkill,
  SYSCALL_truncate,
  SYSCALL_truncate64,
  SYSCALL_ugetrlimit,
  SYSCALL_ulimit,
  SYSCALL_umask,
  SYSCALL_umount,
  SYSCALL_umount2,
  SYSCALL_uname,
  SYSCALL_unlink,
  SYSCALL_unlinkat,
  SYSCALL_unshare,
  SYSCALL_uselib,
  SYSCALL_ustat,
  SYSCALL_utime,
  SYSCALL_utimensat,
  SYSCALL_utimes,
  SYSCALL_vfork,
  SYSCALL_vhangup,
  SYSCALL_vm86,
  SYSCALL_vm86old,
  SYSCALL_vmsplice,
  SYSCALL_vserver,
  SYSCALL_wait4,
  SYSCALL_waitid,
  SYSCALL_waitpid,
  SYSCALL_write,
  SYSCALL_writev,
  SYSCALL_socket,
  SYSCALL_accept,
  SYSCALL_bind,
  SYSCALL_listen,
  SYSCALL_connect,
  SYSCALL_sleep
};

int jelvm_exec(void *code, uint64_t *iv, int ivlen, unsigned int flags, void (*info)(const char *istr));

#endif
