#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "sandbox.h"

#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void)
{
    printf("=== Running seccomp-bpf tests ===\n");

    if (sandbox_seccomp_init() < 0) {
        fprintf(stderr, "FAIL: sandbox_seccomp_init failed: %s\n", strerror(errno));
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

    pid_t pid = getpid();
    assert(pid > 0);
    printf("PASS: getpid() allowed (%d)\n", pid);

    printf("All seccomp tests passed successfully.\n");
    return 0;
}
