#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "sandbox.h"

#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#ifndef TIOCSTI
#define TIOCSTI 0x5412
#endif

#ifndef TIOCLINUX
#define TIOCLINUX 0x541C
#endif

#if defined(__x86_64__)
#define SECCOMP_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define SECCOMP_AUDIT_ARCH AUDIT_ARCH_AARCH64
#elif defined(__i386__)
#define SECCOMP_AUDIT_ARCH AUDIT_ARCH_I386
#elif defined(__arm__)
#define SECCOMP_AUDIT_ARCH AUDIT_ARCH_ARM
#elif defined(__riscv) && __riscv_xlen == 64
#define SECCOMP_AUDIT_ARCH AUDIT_ARCH_RISCV64
#else
#error "unsupported seccomp architecture"
#endif

int sandbox_seccomp_apply(bool block_net, bool block_tiocsti)
{
    if (!block_net && !block_tiocsti) {
        return 0;
    }

    /* security boundary: pr_set_no_new_privs is required before installing unprivileged seccomp filters */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        fprintf(stderr, "safe-agent: prctl(PR_SET_NO_NEW_PRIVS) failed: %s\n", strerror(errno));
        return -1;
    }

    struct sock_filter filter[32];
    size_t idx = 0;

    /* kernel abi quirk: validate architecture to prevent cross-arch syscall number confusion */
    filter[idx++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, arch)));
    filter[idx++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SECCOMP_AUDIT_ARCH, 1, 0);
    filter[idx++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);

    filter[idx++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr)));

#if defined(__x86_64__)
    /* security boundary: prevent x32 abi syscall evasion on x86_64 */
    filter[idx++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x40000000U, 0, 1);
    filter[idx++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
#endif

    if (block_tiocsti) {
        /* security boundary: prevent terminal injection attacks via tiocsti and tioclinux */
        filter[idx++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_ioctl, 0, 4);
        filter[idx++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, args[1])));
        filter[idx++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, TIOCSTI, 1, 0);
        filter[idx++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, TIOCLINUX, 0, 1);
        filter[idx++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
        if (block_net) {
            filter[idx++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr)));
        }
    }

    if (block_net) {
        /* security boundary: return eperm instead of kill to match posix permission denial semantics */
#ifdef __NR_socket
        filter[idx++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socket, 0, 1);
        filter[idx++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
#endif

#ifdef __NR_connect
        filter[idx++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_connect, 0, 1);
        filter[idx++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
#endif

#ifdef __NR_bind
        filter[idx++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_bind, 0, 1);
        filter[idx++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
#endif
    }

    filter[idx++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);

    struct sock_fprog prog = {
        .len = (unsigned short)idx,
        .filter = filter,
    };

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) < 0) {
        fprintf(stderr, "safe-agent: seccomp filter load failed: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

int sandbox_seccomp_init(void)
{
    return sandbox_seccomp_apply(true, false);
}
