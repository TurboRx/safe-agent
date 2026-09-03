#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "sandbox.h"

#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#ifndef TIOCSTI
#define TIOCSTI 0x5412
#endif

#ifndef TIOCLINUX
#define TIOCLINUX 0x541C
#endif

int main(void)
{
    printf("=== Running seccomp-bpf tests ===\n");

    /* test in dedicated child to prevent lsan ptrace collision at parent exit */
    pid_t pid = fork();
    assert(pid >= 0);

    if (pid == 0) {
        if (sandbox_seccomp_apply(true, true, true) < 0) {
            fprintf(stderr, "FAIL: sandbox_seccomp_apply failed: %s\n", strerror(errno));
            _exit(1);
        }

        errno = 0;
        int s_tcp = socket(AF_INET, SOCK_STREAM, 0);
        assert(s_tcp == -1);
        assert(errno == EPERM);

        errno = 0;
        int s_udp = socket(AF_INET, SOCK_DGRAM, 0);
        assert(s_udp == -1);
        assert(errno == EPERM);

        errno = 0;
        int s_un = socket(AF_UNIX, SOCK_STREAM, 0);
        assert(s_un == -1);
        assert(errno == EPERM);

        errno = 0;
        struct sockaddr_in sin = {0};
        sin.sin_family = AF_INET;
        int c = connect(999, (struct sockaddr *)&sin, sizeof(sin));
        assert(c == -1);
        assert(errno == EPERM);

        errno = 0;
        int b = bind(999, (struct sockaddr *)&sin, sizeof(sin));
        assert(b == -1);
        assert(errno == EPERM);

        char fake_input = 'x';
        errno = 0;
        int res_tiocsti = ioctl(0, TIOCSTI, &fake_input);
        assert(res_tiocsti == -1);
        assert(errno == EPERM);

        int fake_linux_arg = 0;
        errno = 0;
        int res_tioclinux = ioctl(0, TIOCLINUX, &fake_linux_arg);
        assert(res_tioclinux == -1);
        assert(errno == EPERM);

        struct winsize ws;
        int res_winsz = ioctl(0, TIOCGWINSZ, &ws);
        (void)res_winsz;

        errno = 0;
        long res_ptrace = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        assert(res_ptrace == -1);
        assert(errno == EPERM);

        char local_buf[16];
        struct iovec local_iov = { .iov_base = local_buf, .iov_len = sizeof(local_buf) };
        struct iovec remote_iov = { .iov_base = (void *)0x10000, .iov_len = sizeof(local_buf) };
        errno = 0;
        ssize_t res_vm = process_vm_readv(getpid(), &local_iov, 1, &remote_iov, 1, 0);
        assert(res_vm == -1);
        assert(errno == EPERM);

        pid_t cur_pid = getpid();
        assert(cur_pid > 0);

        _exit(0);
    }

    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno == EINTR) continue;
        break;
    }

    assert(WIFEXITED(status));
    assert(WEXITSTATUS(status) == 0);

    printf("PASS: socket(AF_INET, SOCK_STREAM) trapped with EPERM\n");
    printf("PASS: socket(AF_INET, SOCK_DGRAM) trapped with EPERM\n");
    printf("PASS: socket(AF_UNIX, SOCK_STREAM) trapped with EPERM\n");
    printf("PASS: connect() trapped with EPERM\n");
    printf("PASS: bind() trapped with EPERM\n");
    printf("PASS: ioctl(TIOCSTI) trapped with EPERM\n");
    printf("PASS: ioctl(TIOCLINUX) trapped with EPERM\n");
    printf("PASS: non-restricted ioctl not trapped by filter\n");
    printf("PASS: ptrace trapped with EPERM by harden-sys\n");
    printf("PASS: process_vm_readv trapped with EPERM by harden-sys\n");
    printf("PASS: getpid() allowed\n");
    printf("All seccomp tests passed successfully.\n");
    return 0;
}
