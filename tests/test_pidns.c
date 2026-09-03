#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "sandbox.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void)
{
    printf("=== Running PID Namespace Isolation (CLONE_NEWPID) Tests ===\n");

    /* test in child so test runner does not unshare its own pid namespace */
    pid_t parent_pid = fork();
    assert(parent_pid >= 0);

    if (parent_pid == 0) {
        int res = sandbox_pidns_unshare();
        assert(res == 0);

        pid_t child = fork();
        assert(child >= 0);

        if (child == 0) {
            /* inside new pid namespace child must be pid 1 */
            if (getpid() != 1) {
                _exit(1);
            }
            _exit(0);
        }

        int child_status = 0;
        waitpid(child, &child_status, 0);
        if (!WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0) {
            _exit(2);
        }
        _exit(0);
    }

    int status = 0;
    while (waitpid(parent_pid, &status, 0) < 0) {
        if (errno == EINTR) continue;
        break;
    }

    assert(WIFEXITED(status));
    assert(WEXITSTATUS(status) == 0);
    printf("PASS: Process table isolated with child running as PID 1\n");

    printf("All PID namespace tests passed successfully.\n");
    return 0;
}
