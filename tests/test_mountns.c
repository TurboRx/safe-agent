#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "sandbox.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void)
{
    printf("=== Running Ephemeral Mounts (tmpfs) Tests ===\n");

    char test_dir[] = "/tmp/safe_agent_tmpfs_XXXXXX";
    char *d = mkdtemp(test_dir);
    assert(d != NULL);

    pid_t pid = fork();
    assert(pid >= 0);

    if (pid == 0) {
        char *paths[1] = { test_dir };
        int res = sandbox_mountns_apply(paths, 1);
        assert(res == 0);

        char file_path[512];
        snprintf(file_path, sizeof(file_path), "%s/secret.txt", test_dir);

        FILE *f = fopen(file_path, "w");
        assert(f != NULL);
        fputs("isolated in ram", f);
        fclose(f);

        _exit(0);
    }

    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno == EINTR) continue;
        break;
    }

    assert(WIFEXITED(status));
    assert(WEXITSTATUS(status) == 0);

    char file_path[512];
    snprintf(file_path, sizeof(file_path), "%s/secret.txt", test_dir);
    FILE *host_check = fopen(file_path, "r");
    assert(host_check == NULL);
    assert(errno == ENOENT);

    rmdir(test_dir);
    printf("PASS: Ephemeral tmpfs isolated in RAM; zero host leak\n");

    printf("All ephemeral mount tests passed successfully.\n");
    return 0;
}
