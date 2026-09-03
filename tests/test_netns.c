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
#include <sys/wait.h>
#include <unistd.h>

int main(void)
{
    printf("=== Running Network Namespace Isolation (CLONE_NEWNET) Tests ===\n");

    pid_t pid = fork();
    assert(pid >= 0);

    if (pid == 0) {
        int res = sandbox_netns_drop();
        if (res < 0) {
            fprintf(stderr, "FAIL: sandbox_netns_drop failed: %s\n", strerror(errno));
            _exit(1);
        }

        /* verify socket creation succeeds inside netns but external connect fails with network unreachable */
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            _exit(2);
        }

        struct sockaddr_in sin = {0};
        sin.sin_family = AF_INET;
        sin.sin_port = htons(80);
        sin.sin_addr.s_addr = htonl(0x08080808); /* 8.8.8.8 */

        int c = connect(fd, (struct sockaddr *)&sin, sizeof(sin));
        if (c == 0) {
            /* connection cannot succeed in an isolated empty netns */
            _exit(3);
        }

        if (errno != ENETUNREACH && errno != EADDRNOTAVAIL) {
            fprintf(stderr, "Unexpected connect errno in netns: %s\n", strerror(errno));
            _exit(4);
        }

        close(fd);
        _exit(0);
    }

    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno == EINTR) continue;
        break;
    }

    assert(WIFEXITED(status));
    assert(WEXITSTATUS(status) == 0);
    printf("PASS: Network namespace unshared and isolated (ENETUNREACH on external connect)\n");

    printf("All network namespace tests passed successfully.\n");
    return 0;
}
