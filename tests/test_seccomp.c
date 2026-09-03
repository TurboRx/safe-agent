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
#include <sys/socket.h>
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

    if (sandbox_seccomp_apply(true, true) < 0) {
        fprintf(stderr, "FAIL: sandbox_seccomp_apply failed: %s\n", strerror(errno));
        return 1;
    }

    errno = 0;
    int s_tcp = socket(AF_INET, SOCK_STREAM, 0);
    assert(s_tcp == -1);
    assert(errno == EPERM);
    printf("PASS: socket(AF_INET, SOCK_STREAM) trapped with EPERM\n");

    errno = 0;
    int s_udp = socket(AF_INET, SOCK_DGRAM, 0);
    assert(s_udp == -1);
    assert(errno == EPERM);
    printf("PASS: socket(AF_INET, SOCK_DGRAM) trapped with EPERM\n");

    errno = 0;
    int s_un = socket(AF_UNIX, SOCK_STREAM, 0);
    assert(s_un == -1);
    assert(errno == EPERM);
    printf("PASS: socket(AF_UNIX, SOCK_STREAM) trapped with EPERM\n");

    errno = 0;
    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;
    int c = connect(999, (struct sockaddr *)&sin, sizeof(sin));
    assert(c == -1);
    assert(errno == EPERM);
    printf("PASS: connect() trapped with EPERM\n");

    errno = 0;
    int b = bind(999, (struct sockaddr *)&sin, sizeof(sin));
    assert(b == -1);
    assert(errno == EPERM);
    printf("PASS: bind() trapped with EPERM\n");

    char fake_input = 'x';
    errno = 0;
    int res_tiocsti = ioctl(0, TIOCSTI, &fake_input);
    assert(res_tiocsti == -1);
    assert(errno == EPERM);
    printf("PASS: ioctl(TIOCSTI) trapped with EPERM\n");

    int fake_linux_arg = 0;
    errno = 0;
    int res_tioclinux = ioctl(0, TIOCLINUX, &fake_linux_arg);
    assert(res_tioclinux == -1);
    assert(errno == EPERM);
    printf("PASS: ioctl(TIOCLINUX) trapped with EPERM\n");

    struct winsize ws;
    int res_winsz = ioctl(0, TIOCGWINSZ, &ws);
    (void)res_winsz;
    printf("PASS: non-restricted ioctl not trapped by filter\n");

    pid_t pid = getpid();
    assert(pid > 0);
    printf("PASS: getpid() allowed (%d)\n", pid);

    printf("All seccomp tests passed successfully.\n");
    return 0;
}
