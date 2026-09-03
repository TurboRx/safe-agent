#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "sandbox.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

static void print_usage(const char *prog_name)
{
    fprintf(stderr,
            "usage: %s --allow-dir <path> [--block-net] -- <command> [args...]\n",
            prog_name);
}

int main(int argc, char **argv)
{
    /* security boundary: validate argument array against zero-length execution vulnerabilities */
    const char *prog_name = (argc > 0 && argv && argv[0]) ? argv[0] : "safe-agent";
    if (argc < 2) {
        print_usage(prog_name);
        return 1;
    }

    const char *allow_dir = NULL;
    bool block_net = false;
    char **command_argv = NULL;

    int i = 1;
    while (i < argc) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(prog_name);
            return 0;
        }
        if (strcmp(argv[i], "--allow-dir") == 0) {
            if (allow_dir != NULL) {
                fprintf(stderr, "safe-agent: error: duplicate --allow-dir option\n");
                print_usage(prog_name);
                return 1;
            }
            if (i + 1 >= argc) {
                fprintf(stderr, "safe-agent: error: --allow-dir requires a path argument\n");
                print_usage(prog_name);
                return 1;
            }
            if (argv[i + 1][0] == '\0') {
                fprintf(stderr, "safe-agent: error: --allow-dir path must not be empty\n");
                print_usage(prog_name);
                return 1;
            }
            allow_dir = argv[i + 1];
            i += 2;
            continue;
        }
        if (strcmp(argv[i], "--block-net") == 0) {
            block_net = true;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--") == 0) {
            i++;
            if (i < argc) {
                command_argv = &argv[i];
            }
            break;
        }
        fprintf(stderr, "safe-agent: error: unrecognized option '%s'\n", argv[i]);
        print_usage(prog_name);
        return 1;
    }

    if (!allow_dir) {
        fprintf(stderr, "safe-agent: error: missing required option --allow-dir\n");
        print_usage(prog_name);
        return 1;
    }

    if (!command_argv || !command_argv[0] || command_argv[0][0] == '\0') {
        fprintf(stderr, "safe-agent: error: missing command after '--'\n");
        print_usage(prog_name);
        return 1;
    }

    /* security boundary: pr_set_no_new_privs prevents execvp targets from gaining privileges */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        fprintf(stderr, "safe-agent: prctl(PR_SET_NO_NEW_PRIVS) failed: %s\n", strerror(errno));
        return 1;
    }

    if (sandbox_landlock_init(allow_dir) < 0) {
        return 1;
    }

    if (block_net) {
        if (sandbox_seccomp_init() < 0) {
            return 1;
        }
    }

    /* security boundary: execvp transfers control to target command replacing current image */
    execvp(command_argv[0], command_argv);

    fprintf(stderr, "safe-agent: failed to execute '%s': %s\n",
            command_argv[0], strerror(errno));
    return (errno == ENOENT) ? 127 : 126;
}
