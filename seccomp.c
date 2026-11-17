/* bubblewrap
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Declarative seccomp policy parsing and cBPF generation.
 */

#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <termios.h>

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#include "seccomp.h"
#include "utils.h"

#ifndef BPF_MAXINSNS
#define BPF_MAXINSNS 4096
#endif

#ifndef SECCOMP_RET_KILL_PROCESS
#define SECCOMP_RET_KILL_PROCESS SECCOMP_RET_KILL
#endif

#if defined(__x86_64__)
#define BWRAP_SECCOMP_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__i386__)
#define BWRAP_SECCOMP_AUDIT_ARCH AUDIT_ARCH_I386
#elif defined(__aarch64__)
#define BWRAP_SECCOMP_AUDIT_ARCH AUDIT_ARCH_AARCH64
#elif defined(__arm__) && defined(__ARMEB__)
#define BWRAP_SECCOMP_AUDIT_ARCH AUDIT_ARCH_ARMEB
#elif defined(__arm__)
#define BWRAP_SECCOMP_AUDIT_ARCH AUDIT_ARCH_ARM
#elif defined(__powerpc64__) && defined(__LITTLE_ENDIAN__)
#define BWRAP_SECCOMP_AUDIT_ARCH AUDIT_ARCH_PPC64LE
#elif defined(__powerpc64__)
#define BWRAP_SECCOMP_AUDIT_ARCH AUDIT_ARCH_PPC64
#elif defined(__powerpc__)
#define BWRAP_SECCOMP_AUDIT_ARCH AUDIT_ARCH_PPC
#elif defined(__s390x__)
#define BWRAP_SECCOMP_AUDIT_ARCH AUDIT_ARCH_S390X
#elif defined(__s390__)
#define BWRAP_SECCOMP_AUDIT_ARCH AUDIT_ARCH_S390
#elif defined(__riscv) && __riscv_xlen == 64
#define BWRAP_SECCOMP_AUDIT_ARCH AUDIT_ARCH_RISCV64
#elif defined(__riscv) && __riscv_xlen == 32
#define BWRAP_SECCOMP_AUDIT_ARCH AUDIT_ARCH_RISCV32
#elif defined(__loongarch__) && __SIZEOF_LONG__ == 8
#define BWRAP_SECCOMP_AUDIT_ARCH AUDIT_ARCH_LOONGARCH64
#elif defined(__loongarch__)
#define BWRAP_SECCOMP_AUDIT_ARCH AUDIT_ARCH_LOONGARCH32
#elif defined(__mips__) && defined(__MIPSEL__) && _MIPS_SIM == _ABIN32
#define BWRAP_SECCOMP_AUDIT_ARCH AUDIT_ARCH_MIPSEL64N32
#elif defined(__mips__) && _MIPS_SIM == _ABIN32
#define BWRAP_SECCOMP_AUDIT_ARCH AUDIT_ARCH_MIPS64N32
#elif defined(__mips__) && defined(__MIPSEL__) && _MIPS_SIM == _ABI64
#define BWRAP_SECCOMP_AUDIT_ARCH AUDIT_ARCH_MIPSEL64
#elif defined(__mips__) && _MIPS_SIM == _ABI64
#define BWRAP_SECCOMP_AUDIT_ARCH AUDIT_ARCH_MIPS64
#elif defined(__mips__) && defined(__MIPSEL__)
#define BWRAP_SECCOMP_AUDIT_ARCH AUDIT_ARCH_MIPSEL
#elif defined(__mips__)
#define BWRAP_SECCOMP_AUDIT_ARCH AUDIT_ARCH_MIPS
#else
#error "No seccomp audit architecture for this platform"
#endif

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define ARG_WORD_0(value) ((uint32_t) ((value) >> 32))
#define ARG_WORD_1(value) ((uint32_t) (value))
#else
#define ARG_WORD_0(value) ((uint32_t) (value))
#define ARG_WORD_1(value) ((uint32_t) ((value) >> 32))
#endif

typedef struct _SeccompArg SeccompArg;
typedef struct _SeccompRule SeccompRule;

typedef enum
{
  SECCOMP_ARG_EQ,
  SECCOMP_ARG_NE,
} SeccompArgOp;

struct _SeccompArg
{
  unsigned int index;
  SeccompArgOp op;
  uint64_t     mask;
  uint64_t     value;
  SeccompArg  *next;
};

struct _SeccompRule
{
  int           syscall_nr;
  uint32_t      action;
  SeccompArg   *args;
  SeccompArg   *last_arg;
  SeccompRule  *next;
};

struct _SeccompPolicy
{
  SeccompRule *rules;
  SeccompRule *last_rule;
  uint32_t     default_action;
};

typedef struct
{
  const char *name;
  uint64_t    value;
} SeccompConstant;

typedef struct
{
  const char *name;
  int         nr;
} SeccompSyscall;

static const SeccompConstant seccomp_errno_constants[] = {
  {"EPERM", EPERM},
  {"ENOENT", ENOENT},
  {"EINTR", EINTR},
  {"EIO", EIO},
  {"ENXIO", ENXIO},
  {"E2BIG", E2BIG},
  {"ENOEXEC", ENOEXEC},
  {"EBADF", EBADF},
  {"ECHILD", ECHILD},
  {"EAGAIN", EAGAIN},
  {"ENOMEM", ENOMEM},
  {"EACCES", EACCES},
  {"EFAULT", EFAULT},
  {"EBUSY", EBUSY},
  {"EEXIST", EEXIST},
  {"EXDEV", EXDEV},
  {"ENODEV", ENODEV},
  {"ENOTDIR", ENOTDIR},
  {"EISDIR", EISDIR},
  {"EINVAL", EINVAL},
  {"ENFILE", ENFILE},
  {"EMFILE", EMFILE},
  {"ENOTTY", ENOTTY},
  {"EFBIG", EFBIG},
  {"ENOSPC", ENOSPC},
  {"ESPIPE", ESPIPE},
  {"EROFS", EROFS},
  {"EMLINK", EMLINK},
  {"EPIPE", EPIPE},
  {"EDOM", EDOM},
  {"ERANGE", ERANGE},
  {"ENOSYS", ENOSYS},
  {"ECONNREFUSED", ECONNREFUSED},
};

static const SeccompConstant seccomp_value_constants[] = {
#ifdef TIOCSTI
  {"TIOCSTI", (uint64_t) (unsigned int) TIOCSTI},
#endif
#ifdef TIOCNOTTY
  {"TIOCNOTTY", (uint64_t) (unsigned int) TIOCNOTTY},
#endif
#ifdef AF_UNIX
  {"AF_UNIX", AF_UNIX},
#endif
#ifdef AF_INET
  {"AF_INET", AF_INET},
#endif
#ifdef AF_INET6
  {"AF_INET6", AF_INET6},
#endif
#ifdef AF_NETLINK
  {"AF_NETLINK", AF_NETLINK},
#endif
  {"SOCK_STREAM", SOCK_STREAM},
  {"SOCK_DGRAM", SOCK_DGRAM},
#ifdef SOCK_RAW
  {"SOCK_RAW", SOCK_RAW},
#endif
#ifdef O_RDONLY
  {"O_RDONLY", O_RDONLY},
#endif
#ifdef O_WRONLY
  {"O_WRONLY", O_WRONLY},
#endif
#ifdef O_RDWR
  {"O_RDWR", O_RDWR},
#endif
#ifdef O_ACCMODE
  {"O_ACCMODE", O_ACCMODE},
#endif
#ifdef O_CLOEXEC
  {"O_CLOEXEC", O_CLOEXEC},
#endif
#ifdef O_CREAT
  {"O_CREAT", O_CREAT},
#endif
#ifdef O_DIRECTORY
  {"O_DIRECTORY", O_DIRECTORY},
#endif
#ifdef O_NOFOLLOW
  {"O_NOFOLLOW", O_NOFOLLOW},
#endif
#ifdef O_PATH
  {"O_PATH", O_PATH},
#endif
#ifdef O_TRUNC
  {"O_TRUNC", O_TRUNC},
#endif
#ifdef AT_FDCWD
  {"AT_FDCWD", (uint64_t) (int64_t) AT_FDCWD},
#endif
#ifdef AT_EMPTY_PATH
  {"AT_EMPTY_PATH", AT_EMPTY_PATH},
#endif
#ifdef AT_REMOVEDIR
  {"AT_REMOVEDIR", AT_REMOVEDIR},
#endif
#ifdef AT_SYMLINK_NOFOLLOW
  {"AT_SYMLINK_NOFOLLOW", AT_SYMLINK_NOFOLLOW},
#endif
#ifdef PROT_READ
  {"PROT_READ", PROT_READ},
#endif
#ifdef PROT_WRITE
  {"PROT_WRITE", PROT_WRITE},
#endif
#ifdef PROT_EXEC
  {"PROT_EXEC", PROT_EXEC},
#endif
#ifdef PROT_NONE
  {"PROT_NONE", PROT_NONE},
#endif
#ifdef MAP_SHARED
  {"MAP_SHARED", MAP_SHARED},
#endif
#ifdef MAP_PRIVATE
  {"MAP_PRIVATE", MAP_PRIVATE},
#endif
#ifdef MAP_ANONYMOUS
  {"MAP_ANONYMOUS", MAP_ANONYMOUS},
#endif
#ifdef MAP_FIXED
  {"MAP_FIXED", MAP_FIXED},
#endif
#ifdef MS_RDONLY
  {"MS_RDONLY", MS_RDONLY},
#endif
#ifdef MS_NOSUID
  {"MS_NOSUID", MS_NOSUID},
#endif
#ifdef MS_NODEV
  {"MS_NODEV", MS_NODEV},
#endif
#ifdef MS_NOEXEC
  {"MS_NOEXEC", MS_NOEXEC},
#endif
#ifdef MS_BIND
  {"MS_BIND", MS_BIND},
#endif
#ifdef MS_REC
  {"MS_REC", MS_REC},
#endif
#ifdef MS_REMOUNT
  {"MS_REMOUNT", MS_REMOUNT},
#endif
#ifdef MS_PRIVATE
  {"MS_PRIVATE", MS_PRIVATE},
#endif
#ifdef MS_SLAVE
  {"MS_SLAVE", MS_SLAVE},
#endif
#ifdef MS_SHARED
  {"MS_SHARED", MS_SHARED},
#endif
#ifdef PR_SET_PDEATHSIG
  {"PR_SET_PDEATHSIG", PR_SET_PDEATHSIG},
#endif
#ifdef PR_SET_SECCOMP
  {"PR_SET_SECCOMP", PR_SET_SECCOMP},
#endif
#ifdef PR_SET_NO_NEW_PRIVS
  {"PR_SET_NO_NEW_PRIVS", PR_SET_NO_NEW_PRIVS},
#endif
#ifdef PR_GET_CHILD_SUBREAPER
  {"PR_GET_CHILD_SUBREAPER", PR_GET_CHILD_SUBREAPER},
#endif
#ifdef CLONE_NEWNS
  {"CLONE_NEWNS", CLONE_NEWNS},
#endif
#ifdef CLONE_NEWUSER
  {"CLONE_NEWUSER", CLONE_NEWUSER},
#endif
#ifdef CLONE_NEWPID
  {"CLONE_NEWPID", CLONE_NEWPID},
#endif
#ifdef CLONE_NEWNET
  {"CLONE_NEWNET", CLONE_NEWNET},
#endif
#ifdef CLONE_NEWIPC
  {"CLONE_NEWIPC", CLONE_NEWIPC},
#endif
#ifdef CLONE_NEWUTS
  {"CLONE_NEWUTS", CLONE_NEWUTS},
#endif
#ifdef CLONE_NEWCGROUP
  {"CLONE_NEWCGROUP", CLONE_NEWCGROUP},
#endif
};

static const SeccompSyscall seccomp_syscalls[] = {
#ifdef __NR_accept
  {"accept", __NR_accept},
#endif
#ifdef __NR_accept4
  {"accept4", __NR_accept4},
#endif
#ifdef __NR_access
  {"access", __NR_access},
#endif
#ifdef __NR_add_key
  {"add_key", __NR_add_key},
#endif
#ifdef __NR_arch_prctl
  {"arch_prctl", __NR_arch_prctl},
#endif
#ifdef __NR_bind
  {"bind", __NR_bind},
#endif
#ifdef __NR_bpf
  {"bpf", __NR_bpf},
#endif
#ifdef __NR_brk
  {"brk", __NR_brk},
#endif
#ifdef __NR_capget
  {"capget", __NR_capget},
#endif
#ifdef __NR_capset
  {"capset", __NR_capset},
#endif
#ifdef __NR_chdir
  {"chdir", __NR_chdir},
#endif
#ifdef __NR_chmod
  {"chmod", __NR_chmod},
#endif
#ifdef __NR_chown
  {"chown", __NR_chown},
#endif
#ifdef __NR_chroot
  {"chroot", __NR_chroot},
#endif
#ifdef __NR_clock_nanosleep
  {"clock_nanosleep", __NR_clock_nanosleep},
#endif
#ifdef __NR_clone
  {"clone", __NR_clone},
#endif
#ifdef __NR_clone3
  {"clone3", __NR_clone3},
#endif
#ifdef __NR_close
  {"close", __NR_close},
#endif
#ifdef __NR_close_range
  {"close_range", __NR_close_range},
#endif
#ifdef __NR_connect
  {"connect", __NR_connect},
#endif
#ifdef __NR_dup
  {"dup", __NR_dup},
#endif
#ifdef __NR_dup2
  {"dup2", __NR_dup2},
#endif
#ifdef __NR_dup3
  {"dup3", __NR_dup3},
#endif
#ifdef __NR_eventfd
  {"eventfd", __NR_eventfd},
#endif
#ifdef __NR_eventfd2
  {"eventfd2", __NR_eventfd2},
#endif
#ifdef __NR_execve
  {"execve", __NR_execve},
#endif
#ifdef __NR_execveat
  {"execveat", __NR_execveat},
#endif
#ifdef __NR_exit
  {"exit", __NR_exit},
#endif
#ifdef __NR_exit_group
  {"exit_group", __NR_exit_group},
#endif
#ifdef __NR_faccessat
  {"faccessat", __NR_faccessat},
#endif
#ifdef __NR_faccessat2
  {"faccessat2", __NR_faccessat2},
#endif
#ifdef __NR_fchmod
  {"fchmod", __NR_fchmod},
#endif
#ifdef __NR_fchmodat
  {"fchmodat", __NR_fchmodat},
#endif
#ifdef __NR_fchown
  {"fchown", __NR_fchown},
#endif
#ifdef __NR_fchownat
  {"fchownat", __NR_fchownat},
#endif
#ifdef __NR_fcntl
  {"fcntl", __NR_fcntl},
#endif
#ifdef __NR_finit_module
  {"finit_module", __NR_finit_module},
#endif
#ifdef __NR_fork
  {"fork", __NR_fork},
#endif
#ifdef __NR_fstat
  {"fstat", __NR_fstat},
#endif
#ifdef __NR_fstatat64
  {"fstatat64", __NR_fstatat64},
#endif
#ifdef __NR_fsync
  {"fsync", __NR_fsync},
#endif
#ifdef __NR_ftruncate
  {"ftruncate", __NR_ftruncate},
#endif
#ifdef __NR_futex
  {"futex", __NR_futex},
#endif
#ifdef __NR_getdents64
  {"getdents64", __NR_getdents64},
#endif
#ifdef __NR_getpid
  {"getpid", __NR_getpid},
#endif
#ifdef __NR_getrandom
  {"getrandom", __NR_getrandom},
#endif
#ifdef __NR_gettid
  {"gettid", __NR_gettid},
#endif
#ifdef __NR_init_module
  {"init_module", __NR_init_module},
#endif
#ifdef __NR_io_uring_enter
  {"io_uring_enter", __NR_io_uring_enter},
#endif
#ifdef __NR_io_uring_register
  {"io_uring_register", __NR_io_uring_register},
#endif
#ifdef __NR_io_uring_setup
  {"io_uring_setup", __NR_io_uring_setup},
#endif
#ifdef __NR_ioctl
  {"ioctl", __NR_ioctl},
#endif
#ifdef __NR_keyctl
  {"keyctl", __NR_keyctl},
#endif
#ifdef __NR_kill
  {"kill", __NR_kill},
#endif
#ifdef __NR_link
  {"link", __NR_link},
#endif
#ifdef __NR_linkat
  {"linkat", __NR_linkat},
#endif
#ifdef __NR_listen
  {"listen", __NR_listen},
#endif
#ifdef __NR_lseek
  {"lseek", __NR_lseek},
#endif
#ifdef __NR_lstat
  {"lstat", __NR_lstat},
#endif
#ifdef __NR_madvise
  {"madvise", __NR_madvise},
#endif
#ifdef __NR_memfd_create
  {"memfd_create", __NR_memfd_create},
#endif
#ifdef __NR_mkdir
  {"mkdir", __NR_mkdir},
#endif
#ifdef __NR_mkdirat
  {"mkdirat", __NR_mkdirat},
#endif
#ifdef __NR_mmap
  {"mmap", __NR_mmap},
#endif
#ifdef __NR_mount
  {"mount", __NR_mount},
#endif
#ifdef __NR_mprotect
  {"mprotect", __NR_mprotect},
#endif
#ifdef __NR_mremap
  {"mremap", __NR_mremap},
#endif
#ifdef __NR_munmap
  {"munmap", __NR_munmap},
#endif
#ifdef __NR_nanosleep
  {"nanosleep", __NR_nanosleep},
#endif
#ifdef __NR_newfstatat
  {"newfstatat", __NR_newfstatat},
#endif
#ifdef __NR_open
  {"open", __NR_open},
#endif
#ifdef __NR_openat
  {"openat", __NR_openat},
#endif
#ifdef __NR_openat2
  {"openat2", __NR_openat2},
#endif
#ifdef __NR_perf_event_open
  {"perf_event_open", __NR_perf_event_open},
#endif
#ifdef __NR_personality
  {"personality", __NR_personality},
#endif
#ifdef __NR_pidfd_getfd
  {"pidfd_getfd", __NR_pidfd_getfd},
#endif
#ifdef __NR_pidfd_open
  {"pidfd_open", __NR_pidfd_open},
#endif
#ifdef __NR_pidfd_send_signal
  {"pidfd_send_signal", __NR_pidfd_send_signal},
#endif
#ifdef __NR_pipe
  {"pipe", __NR_pipe},
#endif
#ifdef __NR_pipe2
  {"pipe2", __NR_pipe2},
#endif
#ifdef __NR_pivot_root
  {"pivot_root", __NR_pivot_root},
#endif
#ifdef __NR_poll
  {"poll", __NR_poll},
#endif
#ifdef __NR_prctl
  {"prctl", __NR_prctl},
#endif
#ifdef __NR_pread64
  {"pread64", __NR_pread64},
#endif
#ifdef __NR_process_vm_readv
  {"process_vm_readv", __NR_process_vm_readv},
#endif
#ifdef __NR_process_vm_writev
  {"process_vm_writev", __NR_process_vm_writev},
#endif
#ifdef __NR_ptrace
  {"ptrace", __NR_ptrace},
#endif
#ifdef __NR_pwrite64
  {"pwrite64", __NR_pwrite64},
#endif
#ifdef __NR_read
  {"read", __NR_read},
#endif
#ifdef __NR_readlink
  {"readlink", __NR_readlink},
#endif
#ifdef __NR_readlinkat
  {"readlinkat", __NR_readlinkat},
#endif
#ifdef __NR_readv
  {"readv", __NR_readv},
#endif
#ifdef __NR_reboot
  {"reboot", __NR_reboot},
#endif
#ifdef __NR_recvfrom
  {"recvfrom", __NR_recvfrom},
#endif
#ifdef __NR_recvmsg
  {"recvmsg", __NR_recvmsg},
#endif
#ifdef __NR_rename
  {"rename", __NR_rename},
#endif
#ifdef __NR_renameat
  {"renameat", __NR_renameat},
#endif
#ifdef __NR_renameat2
  {"renameat2", __NR_renameat2},
#endif
#ifdef __NR_request_key
  {"request_key", __NR_request_key},
#endif
#ifdef __NR_rmdir
  {"rmdir", __NR_rmdir},
#endif
#ifdef __NR_rt_sigaction
  {"rt_sigaction", __NR_rt_sigaction},
#endif
#ifdef __NR_rt_sigprocmask
  {"rt_sigprocmask", __NR_rt_sigprocmask},
#endif
#ifdef __NR_rt_sigreturn
  {"rt_sigreturn", __NR_rt_sigreturn},
#endif
#ifdef __NR_sched_getaffinity
  {"sched_getaffinity", __NR_sched_getaffinity},
#endif
#ifdef __NR_sched_yield
  {"sched_yield", __NR_sched_yield},
#endif
#ifdef __NR_seccomp
  {"seccomp", __NR_seccomp},
#endif
#ifdef __NR_sendfile
  {"sendfile", __NR_sendfile},
#endif
#ifdef __NR_sendmsg
  {"sendmsg", __NR_sendmsg},
#endif
#ifdef __NR_sendto
  {"sendto", __NR_sendto},
#endif
#ifdef __NR_setdomainname
  {"setdomainname", __NR_setdomainname},
#endif
#ifdef __NR_setgid
  {"setgid", __NR_setgid},
#endif
#ifdef __NR_setgroups
  {"setgroups", __NR_setgroups},
#endif
#ifdef __NR_sethostname
  {"sethostname", __NR_sethostname},
#endif
#ifdef __NR_setns
  {"setns", __NR_setns},
#endif
#ifdef __NR_setregid
  {"setregid", __NR_setregid},
#endif
#ifdef __NR_setresgid
  {"setresgid", __NR_setresgid},
#endif
#ifdef __NR_setresuid
  {"setresuid", __NR_setresuid},
#endif
#ifdef __NR_setreuid
  {"setreuid", __NR_setreuid},
#endif
#ifdef __NR_setsockopt
  {"setsockopt", __NR_setsockopt},
#endif
#ifdef __NR_setuid
  {"setuid", __NR_setuid},
#endif
#ifdef __NR_shutdown
  {"shutdown", __NR_shutdown},
#endif
#ifdef __NR_sigaltstack
  {"sigaltstack", __NR_sigaltstack},
#endif
#ifdef __NR_socket
  {"socket", __NR_socket},
#endif
#ifdef __NR_socketpair
  {"socketpair", __NR_socketpair},
#endif
#ifdef __NR_splice
  {"splice", __NR_splice},
#endif
#ifdef __NR_stat
  {"stat", __NR_stat},
#endif
#ifdef __NR_statx
  {"statx", __NR_statx},
#endif
#ifdef __NR_symlink
  {"symlink", __NR_symlink},
#endif
#ifdef __NR_symlinkat
  {"symlinkat", __NR_symlinkat},
#endif
#ifdef __NR_sync
  {"sync", __NR_sync},
#endif
#ifdef __NR_syncfs
  {"syncfs", __NR_syncfs},
#endif
#ifdef __NR_sysinfo
  {"sysinfo", __NR_sysinfo},
#endif
#ifdef __NR_tee
  {"tee", __NR_tee},
#endif
#ifdef __NR_tgkill
  {"tgkill", __NR_tgkill},
#endif
#ifdef __NR_tkill
  {"tkill", __NR_tkill},
#endif
#ifdef __NR_truncate
  {"truncate", __NR_truncate},
#endif
#ifdef __NR_umount2
  {"umount2", __NR_umount2},
#endif
#ifdef __NR_uname
  {"uname", __NR_uname},
#endif
#ifdef __NR_unlink
  {"unlink", __NR_unlink},
#endif
#ifdef __NR_unlinkat
  {"unlinkat", __NR_unlinkat},
#endif
#ifdef __NR_unshare
  {"unshare", __NR_unshare},
#endif
#ifdef __NR_userfaultfd
  {"userfaultfd", __NR_userfaultfd},
#endif
#ifdef __NR_vfork
  {"vfork", __NR_vfork},
#endif
#ifdef __NR_vmsplice
  {"vmsplice", __NR_vmsplice},
#endif
#ifdef __NR_wait4
  {"wait4", __NR_wait4},
#endif
#ifdef __NR_write
  {"write", __NR_write},
#endif
#ifdef __NR_writev
  {"writev", __NR_writev},
#endif
};

typedef struct _BpfLabel BpfLabel;
typedef struct _BpfJumpRef BpfJumpRef;
typedef struct _BpfBuilder BpfBuilder;

struct _BpfLabel
{
  size_t offset;
  bool   bound;
};

struct _BpfJumpRef
{
  size_t       instruction;
  bool         true_branch;
  BpfLabel    *label;
  BpfJumpRef  *next;
};

struct _BpfBuilder
{
  struct sock_filter *instructions;
  size_t              len;
  size_t              allocated;
  BpfJumpRef         *jump_refs;
};

static uint64_t
parse_constant (const char               *value,
                const SeccompConstant    *constants,
                size_t                    n_constants,
                const char               *description)
{
  char *end = NULL;
  unsigned long long parsed;
  size_t i;

  if (value[0] == '-')
    die ("Invalid seccomp %s: %s", description, value);

  errno = 0;
  parsed = strtoull (value, &end, 0);
  if (value[0] != '\0' && end != NULL && end[0] == '\0' && errno != ERANGE)
    return parsed;

  for (i = 0; i < n_constants; i++)
    {
      if (strcmp (value, constants[i].name) == 0)
        return constants[i].value;
    }

  die ("Invalid seccomp %s: %s", description, value);
}

static int
parse_syscall (const char *name)
{
  char *end = NULL;
  unsigned long parsed;
  size_t i;

  errno = 0;
  parsed = strtoul (name, &end, 0);
  if (name[0] != '\0' && end != NULL && end[0] == '\0' &&
      errno != ERANGE && parsed <= INT_MAX)
    return (int) parsed;

  for (i = 0; i < N_ELEMENTS (seccomp_syscalls); i++)
    {
      if (strcmp (name, seccomp_syscalls[i].name) == 0)
        return seccomp_syscalls[i].nr;
    }

  die ("Unknown seccomp syscall: %s (use a numeric syscall number for "
       "syscalls not in bwrap's name table)", name);
}

static uint32_t
parse_action (const char *action)
{
  uint64_t value;

  if (strcmp (action, "allow") == 0)
    return SECCOMP_RET_ALLOW;
  if (strcmp (action, "kill") == 0)
    return SECCOMP_RET_KILL_PROCESS;
  if (strcmp (action, "trap") == 0)
    return SECCOMP_RET_TRAP;
  if (strcmp (action, "log") == 0)
    return SECCOMP_RET_LOG;

  if (has_prefix (action, "errno:"))
    {
      value = parse_constant (action + strlen ("errno:"),
                              seccomp_errno_constants,
                              N_ELEMENTS (seccomp_errno_constants),
                              "errno");
      if (value > SECCOMP_RET_DATA)
        die ("Seccomp errno is out of range: %s", action);

      return SECCOMP_RET_ERRNO | (uint32_t) value;
    }

  die ("Invalid seccomp action: %s (expected allow, kill, trap, log, or "
       "errno:ERRNO)", action);
}

static unsigned int
parse_arg_index (const char *arg)
{
  char *end = NULL;
  unsigned long index;

  if (has_prefix (arg, "arg"))
    arg += strlen ("arg");

  errno = 0;
  index = strtoul (arg, &end, 10);
  if (arg[0] != '\0' && end != NULL && end[0] == '\0' &&
      errno != ERANGE && index < 6)
    return (unsigned int) index;

  die ("Invalid seccomp syscall argument: %s (expected arg0 to arg5)",
       arg);
}

static void
seccomp_arg_append (SeccompRule *rule,
                    SeccompArg  *arg)
{
  if (rule->last_arg != NULL)
    rule->last_arg->next = arg;
  else
    rule->args = arg;

  rule->last_arg = arg;
}

static BpfLabel *
bpf_label_new (void)
{
  return xcalloc (1, sizeof (BpfLabel));
}

static void
bpf_label_bind (BpfLabel *label,
                size_t    offset)
{
  if (label->bound)
    die ("Internal error: seccomp BPF label bound twice");

  label->offset = offset;
  label->bound = true;
}

static size_t
bpf_add (BpfBuilder         *builder,
         struct sock_filter  instruction)
{
  if (builder->len >= BPF_MAXINSNS)
    die ("Declarative seccomp policy is too large");

  if (builder->len == builder->allocated)
    {
      builder->allocated = builder->allocated == 0 ? 64 : builder->allocated * 2;
      builder->instructions =
        xrealloc (builder->instructions,
                  builder->allocated * sizeof (struct sock_filter));
    }

  builder->instructions[builder->len] = instruction;
  return builder->len++;
}

static void
bpf_add_jump_ref (BpfBuilder *builder,
                  size_t      instruction,
                  bool        true_branch,
                  BpfLabel   *label)
{
  BpfJumpRef *ref;

  if (label == NULL)
    return;

  ref = xcalloc (1, sizeof (BpfJumpRef));
  ref->instruction = instruction;
  ref->true_branch = true_branch;
  ref->label = label;
  ref->next = builder->jump_refs;
  builder->jump_refs = ref;
}

static size_t
bpf_add_jump (BpfBuilder *builder,
              uint16_t    code,
              uint32_t    value,
              BpfLabel   *true_label,
              BpfLabel   *false_label)
{
  size_t instruction;

  instruction = bpf_add (builder, (struct sock_filter) BPF_JUMP (code, value, 0, 0));
  bpf_add_jump_ref (builder, instruction, true, true_label);
  bpf_add_jump_ref (builder, instruction, false, false_label);
  return instruction;
}

static void
bpf_load_absolute (BpfBuilder *builder,
                   size_t      offset)
{
  bpf_add (builder, (struct sock_filter) BPF_STMT (BPF_LD | BPF_W | BPF_ABS, offset));
}

static void
bpf_and_constant (BpfBuilder *builder,
                  uint32_t    mask)
{
  bpf_add (builder, (struct sock_filter) BPF_STMT (BPF_ALU | BPF_AND | BPF_K, mask));
}

static void
bpf_return (BpfBuilder *builder,
            uint32_t    action)
{
  bpf_add (builder, (struct sock_filter) BPF_STMT (BPF_RET | BPF_K, action));
}

static size_t
bpf_arg_offset (unsigned int arg,
                unsigned int word)
{
  return offsetof (struct seccomp_data, args) +
         arg * sizeof (uint64_t) + word * sizeof (uint32_t);
}

static void
bpf_add_arg_predicate (BpfBuilder  *builder,
                       SeccompArg  *predicate,
                       BpfLabel    *fail_label)
{
  BpfLabel *success_label = NULL;
  uint64_t expected;
  uint32_t expected_0;
  uint32_t expected_1;
  uint32_t mask_0;
  uint32_t mask_1;

  expected = predicate->value & predicate->mask;
  expected_0 = ARG_WORD_0 (expected);
  expected_1 = ARG_WORD_1 (expected);
  mask_0 = ARG_WORD_0 (predicate->mask);
  mask_1 = ARG_WORD_1 (predicate->mask);

  if (predicate->op == SECCOMP_ARG_NE)
    success_label = bpf_label_new ();

  bpf_load_absolute (builder, bpf_arg_offset (predicate->index, 0));
  bpf_and_constant (builder, mask_0);
  bpf_add_jump (builder, BPF_JMP | BPF_JEQ | BPF_K, expected_0,
                NULL,
                predicate->op == SECCOMP_ARG_EQ ? fail_label : success_label);

  bpf_load_absolute (builder, bpf_arg_offset (predicate->index, 1));
  bpf_and_constant (builder, mask_1);
  bpf_add_jump (builder, BPF_JMP | BPF_JEQ | BPF_K, expected_1,
                predicate->op == SECCOMP_ARG_EQ ? NULL : fail_label,
                predicate->op == SECCOMP_ARG_EQ ? fail_label : NULL);

  if (success_label != NULL)
    bpf_label_bind (success_label, builder->len);
}

static void
bpf_finish_jumps (BpfBuilder *builder)
{
  BpfJumpRef *ref;

  for (ref = builder->jump_refs; ref != NULL; ref = ref->next)
    {
      size_t offset;

      if (!ref->label->bound)
        die ("Internal error: unbound seccomp BPF label");

      if (ref->label->offset < ref->instruction + 1)
        die ("Internal error: backward seccomp BPF jump");

      offset = ref->label->offset - ref->instruction - 1;
      if (offset > UINT8_MAX)
        die ("Declarative seccomp policy is too complex to encode");

      if (ref->true_branch)
        builder->instructions[ref->instruction].jt = (uint8_t) offset;
      else
        builder->instructions[ref->instruction].jf = (uint8_t) offset;
    }
}

static bool
rules_have_same_syscall (SeccompRule *rule,
                         int          syscall_nr)
{
  return rule != NULL && rule->syscall_nr == syscall_nr;
}

static void
seccomp_policy_compile_rules (SeccompPolicy *policy,
                              BpfBuilder    *builder)
{
  SeccompRule *rule = policy->rules;

  while (rule != NULL)
    {
      BpfLabel *next_group_label = bpf_label_new ();
      int syscall_nr = rule->syscall_nr;

      bpf_load_absolute (builder, offsetof (struct seccomp_data, nr));
      bpf_add_jump (builder, BPF_JMP | BPF_JEQ | BPF_K, syscall_nr,
                    NULL, next_group_label);

      while (rules_have_same_syscall (rule, syscall_nr))
        {
          BpfLabel *next_rule_label = bpf_label_new ();
          SeccompArg *arg;

          for (arg = rule->args; arg != NULL; arg = arg->next)
            bpf_add_arg_predicate (builder, arg, next_rule_label);

          bpf_return (builder, rule->action);
          bpf_label_bind (next_rule_label, builder->len);
          rule = rule->next;
        }

      bpf_label_bind (next_group_label, builder->len);
    }
}

SeccompPolicy *
seccomp_policy_new (void)
{
  SeccompPolicy *policy = xcalloc (1, sizeof (SeccompPolicy));

  policy->default_action = SECCOMP_RET_ALLOW;
  return policy;
}

void
seccomp_policy_free (SeccompPolicy *policy)
{
  SeccompRule *rule;
  SeccompRule *next_rule;

  if (policy == NULL)
    return;

  for (rule = policy->rules; rule != NULL; rule = next_rule)
    {
      SeccompArg *arg;
      SeccompArg *next_arg;

      next_rule = rule->next;
      for (arg = rule->args; arg != NULL; arg = next_arg)
        {
          next_arg = arg->next;
          free (arg);
        }
      free (rule);
    }

  free (policy);
}

void
seccomp_policy_set_default_action (SeccompPolicy *policy,
                                   const char    *action)
{
  policy->default_action = parse_action (action);
}

void
seccomp_policy_add_rule (SeccompPolicy *policy,
                         const char    *spec)
{
  cleanup_free char *copy = xstrdup (spec);
  char *saveptr = NULL;
  char *action_token;
  char *syscall_token;
  char *arg_token;
  SeccompRule *rule;

  action_token = strtok_r (copy, " \t", &saveptr);
  if (action_token == NULL)
    die ("Empty --seccomp-rule");

  syscall_token = strtok_r (NULL, " \t", &saveptr);
  if (syscall_token == NULL)
    die ("--seccomp-rule requires a syscall name");

  rule = xcalloc (1, sizeof (SeccompRule));
  rule->action = parse_action (action_token);
  rule->syscall_nr = parse_syscall (syscall_token);

  while ((arg_token = strtok_r (NULL, " \t", &saveptr)) != NULL)
    {
      SeccompArg *arg = xcalloc (1, sizeof (SeccompArg));
      char *operator_token;
      char *value_token;

      arg->index = parse_arg_index (arg_token);
      arg->mask = UINT64_MAX;

      operator_token = strtok_r (NULL, " \t", &saveptr);
      if (operator_token == NULL)
        die ("--seccomp-rule argument %s is missing an operator", arg_token);

      if (strcmp (operator_token, "&") == 0)
        {
          char *mask_token = strtok_r (NULL, " \t", &saveptr);

          if (mask_token == NULL)
            die ("--seccomp-rule argument %s is missing a mask", arg_token);

          arg->mask = parse_constant (mask_token,
                                      seccomp_value_constants,
                                      N_ELEMENTS (seccomp_value_constants),
                                      "mask");

          operator_token = strtok_r (NULL, " \t", &saveptr);
          if (operator_token == NULL)
            die ("--seccomp-rule argument %s is missing a comparison",
                 arg_token);
        }

      if (strcmp (operator_token, "==") == 0)
        arg->op = SECCOMP_ARG_EQ;
      else if (strcmp (operator_token, "!=") == 0)
        arg->op = SECCOMP_ARG_NE;
      else
        die ("Invalid seccomp argument operator: %s (expected == or !=)",
             operator_token);

      value_token = strtok_r (NULL, " \t", &saveptr);
      if (value_token == NULL)
        die ("--seccomp-rule argument %s is missing a value", arg_token);

      arg->value = parse_constant (value_token,
                                   seccomp_value_constants,
                                   N_ELEMENTS (seccomp_value_constants),
                                   "value");
      seccomp_arg_append (rule, arg);
    }

  if (policy->last_rule != NULL)
    policy->last_rule->next = rule;
  else
    policy->rules = rule;

  policy->last_rule = rule;
}

struct sock_fprog *
seccomp_policy_compile (SeccompPolicy *policy)
{
  BpfBuilder builder = { 0 };
  struct sock_fprog *program;

  bpf_load_absolute (&builder, offsetof (struct seccomp_data, arch));
  bpf_add (&builder, (struct sock_filter)
           BPF_JUMP (BPF_JMP | BPF_JEQ | BPF_K,
                     BWRAP_SECCOMP_AUDIT_ARCH, 1, 0));
  bpf_add (&builder, (struct sock_filter) BPF_STMT (BPF_RET | BPF_K,
                                                    SECCOMP_RET_ERRNO | ENOSYS));

#if defined(__x86_64__)
  bpf_load_absolute (&builder, offsetof (struct seccomp_data, nr));
  bpf_add (&builder, (struct sock_filter)
           BPF_JUMP (BPF_JMP | BPF_JSET | BPF_K, 0x40000000, 0, 1));
  bpf_add (&builder, (struct sock_filter) BPF_STMT (BPF_RET | BPF_K,
                                                    SECCOMP_RET_ERRNO | ENOSYS));
#endif

  seccomp_policy_compile_rules (policy, &builder);
  bpf_return (&builder, policy->default_action);

  bpf_finish_jumps (&builder);

  program = xcalloc (1, sizeof (struct sock_fprog));
  program->len = builder.len;
  program->filter = builder.instructions;
  return program;
}
