#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "sandbox.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void)
{
    printf("=== Running Policy Profile Tests ===\n");

    char profile_path[] = "/tmp/safe_agent_prof_XXXXXX.conf";
    int fd = mkstemps(profile_path, 5);
    assert(fd >= 0);

    const char *content = "# base runner profile\n"
                          "allow-dir=/tmp\n"
                          "timeout=15\n"
                          "block-net\n"
                          "env=PROF_ENV=hello\n";
    ssize_t wr = write(fd, content, strlen(content));
    assert(wr == (ssize_t)strlen(content));
    close(fd);

    char *orig_argv[] = {
        "./safe-agent",
        "--profile",
        profile_path,
        "--",
        "/bin/echo",
        "profile_test",
        NULL
    };
    int orig_argc = 6;

    int out_argc = 0;
    char **out_argv = NULL;
    int res = sandbox_profile_expand(orig_argc, orig_argv, &out_argc, &out_argv);
    assert(res == 1);
    assert(out_argv != NULL);
    assert(out_argc > orig_argc);

    bool found_allow_dir = false;
    bool found_timeout = false;
    bool found_block_net = false;
    bool found_env = false;

    for (int i = 0; i < out_argc; i++) {
        if (strcmp(out_argv[i], "--allow-dir") == 0 && i + 1 < out_argc && strcmp(out_argv[i+1], "/tmp") == 0) {
            found_allow_dir = true;
        }
        if (strcmp(out_argv[i], "--timeout") == 0 && i + 1 < out_argc && strcmp(out_argv[i+1], "15") == 0) {
            found_timeout = true;
        }
        if (strcmp(out_argv[i], "--block-net") == 0) {
            found_block_net = true;
        }
        if (strcmp(out_argv[i], "--env") == 0 && i + 1 < out_argc && strcmp(out_argv[i+1], "PROF_ENV=hello") == 0) {
            found_env = true;
        }
    }

    assert(found_allow_dir);
    assert(found_timeout);
    assert(found_block_net);
    assert(found_env);

    sandbox_profile_free(out_argc, out_argv, orig_argv);
    unlink(profile_path);

    printf("PASS: Declarative policy profile parsed and expanded cleanly\n");
    printf("All policy profile tests passed successfully.\n");
    return 0;
}
