#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "sandbox.h"

#include <assert.h>
#include <stdio.h>
#include <unistd.h>

int sandbox_landlock_init_paths(char *const *allow_dirs,
                                size_t allow_dir_count,
                                char *const *ro_dirs,
                                size_t ro_dir_count)
{
    (void)allow_dirs;
    (void)allow_dir_count;
    (void)ro_dirs;
    (void)ro_dir_count;
    return 0;
}

int sandbox_seccomp_init(void)
{
    return 0;
}

int main(void)
{
    printf("=== Running Process Timeout & Supervisor Tests ===\n");

    char *dirs[] = { "/tmp" };

    /* test 1: fast command succeeds */
    char *cmd1[] = { "/bin/true", NULL };
    struct sandbox_exec_args args1 = {
        .allow_dirs = dirs,
        .allow_dir_count = 1,
        .ro_dirs = NULL,
        .ro_dir_count = 0,
        .block_net = false,
        .clean_env = false,
        .keep_keys = NULL,
        .keep_count = 0,
        .set_pairs = NULL,
        .set_count = 0,
        .command_argv = cmd1,
    };
    int res1 = sandbox_supervisor_execute(3, &args1);
    assert(res1 == 0);
    printf("PASS: Fast command finishes within timeout (exit 0)\n");

    /* test 2: slow command triggers timeout */
    char *cmd2[] = { "/bin/sleep", "10", NULL };
    struct sandbox_exec_args args2 = {
        .allow_dirs = dirs,
        .allow_dir_count = 1,
        .ro_dirs = NULL,
        .ro_dir_count = 0,
        .block_net = false,
        .clean_env = false,
        .keep_keys = NULL,
        .keep_count = 0,
        .set_pairs = NULL,
        .set_count = 0,
        .command_argv = cmd2,
    };
    int res2 = sandbox_supervisor_execute(1, &args2);
    assert(res2 == 124);
    printf("PASS: Slow command terminated after timeout (exit 124)\n");

    /* test 3: command exiting with non-zero code */
    char *cmd3[] = { "/bin/sh", "-c", "exit 42", NULL };
    struct sandbox_exec_args args3 = {
        .allow_dirs = dirs,
        .allow_dir_count = 1,
        .ro_dirs = NULL,
        .ro_dir_count = 0,
        .block_net = false,
        .clean_env = false,
        .keep_keys = NULL,
        .keep_count = 0,
        .set_pairs = NULL,
        .set_count = 0,
        .command_argv = cmd3,
    };
    int res3 = sandbox_supervisor_execute(3, &args3);
    assert(res3 == 42);
    printf("PASS: Command exit status preserved (exit 42)\n");

    printf("All supervisor tests passed successfully.\n");
    return 0;
}
