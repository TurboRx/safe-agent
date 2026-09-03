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
            "usage: %s --allow-dir <path> [--block-net] [--clean-env] [--env KEY=VAL] [--keep-env KEY] -- <command> [args...]\n",
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
    bool clean_env = false;
    char **keep_keys = NULL;
    size_t keep_count = 0;
    size_t keep_cap = 0;
    char **set_pairs = NULL;
    size_t set_count = 0;
    size_t set_cap = 0;
    char **command_argv = NULL;

    int i = 1;
    while (i < argc) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(prog_name);
            free(keep_keys);
            free(set_pairs);
            return 0;
        }
        if (strcmp(argv[i], "--allow-dir") == 0) {
            if (allow_dir != NULL) {
                fprintf(stderr, "safe-agent: error: duplicate --allow-dir option\n");
                print_usage(prog_name);
                free(keep_keys);
                free(set_pairs);
                return 1;
            }
            if (i + 1 >= argc || strncmp(argv[i + 1], "--", 2) == 0) {
                fprintf(stderr, "safe-agent: error: --allow-dir requires a path argument\n");
                print_usage(prog_name);
                free(keep_keys);
                free(set_pairs);
                return 1;
            }
            if (argv[i + 1][0] == '\0') {
                fprintf(stderr, "safe-agent: error: --allow-dir path must not be empty\n");
                print_usage(prog_name);
                free(keep_keys);
                free(set_pairs);
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
        if (strcmp(argv[i], "--clean-env") == 0) {
            clean_env = true;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--env") == 0) {
            if (i + 1 >= argc || strcmp(argv[i + 1], "--") == 0) {
                fprintf(stderr, "safe-agent: error: --env requires a KEY=VAL argument\n");
                print_usage(prog_name);
                free(keep_keys);
                free(set_pairs);
                return 1;
            }
            const char *eq = strchr(argv[i + 1], '=');
            if (!eq || eq == argv[i + 1]) {
                fprintf(stderr, "safe-agent: error: --env requires format KEY=VAL with non-empty KEY\n");
                print_usage(prog_name);
                free(keep_keys);
                free(set_pairs);
                return 1;
            }
            if (set_count == set_cap) {
                size_t new_cap = (set_cap == 0) ? 4 : set_cap * 2;
                char **tmp = realloc(set_pairs, new_cap * sizeof(char *));
                if (!tmp) {
                    fprintf(stderr, "safe-agent: out of memory for env pairs\n");
                    free(keep_keys);
                    free(set_pairs);
                    return 1;
                }
                set_pairs = tmp;
                set_cap = new_cap;
            }
            set_pairs[set_count++] = argv[i + 1];
            i += 2;
            continue;
        }
        if (strcmp(argv[i], "--keep-env") == 0) {
            if (i + 1 >= argc || strcmp(argv[i + 1], "--") == 0) {
                fprintf(stderr, "safe-agent: error: --keep-env requires a KEY argument\n");
                print_usage(prog_name);
                free(keep_keys);
                free(set_pairs);
                return 1;
            }
            if (argv[i + 1][0] == '\0' || strchr(argv[i + 1], '=')) {
                fprintf(stderr, "safe-agent: error: --keep-env requires a valid variable name\n");
                print_usage(prog_name);
                free(keep_keys);
                free(set_pairs);
                return 1;
            }
            if (keep_count == keep_cap) {
                size_t new_cap = (keep_cap == 0) ? 4 : keep_cap * 2;
                char **tmp = realloc(keep_keys, new_cap * sizeof(char *));
                if (!tmp) {
                    fprintf(stderr, "safe-agent: out of memory for keep env\n");
                    free(keep_keys);
                    free(set_pairs);
                    return 1;
                }
                keep_keys = tmp;
                keep_cap = new_cap;
            }
            keep_keys[keep_count++] = argv[i + 1];
            i += 2;
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
        free(keep_keys);
        free(set_pairs);
        return 1;
    }

    if (!allow_dir) {
        fprintf(stderr, "safe-agent: error: missing required option --allow-dir\n");
        print_usage(prog_name);
        free(keep_keys);
        free(set_pairs);
        return 1;
    }

    if (!command_argv || !command_argv[0] || command_argv[0][0] == '\0') {
        fprintf(stderr, "safe-agent: error: missing command after '--'\n");
        print_usage(prog_name);
        free(keep_keys);
        free(set_pairs);
        return 1;
    }

    /* security boundary: pr_set_no_new_privs prevents execvp targets from gaining privileges */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        fprintf(stderr, "safe-agent: prctl(PR_SET_NO_NEW_PRIVS) failed: %s\n", strerror(errno));
        free(keep_keys);
        free(set_pairs);
        return 1;
    }

    if (sandbox_landlock_init(allow_dir) < 0) {
        free(keep_keys);
        free(set_pairs);
        return 1;
    }

    if (block_net) {
        if (sandbox_seccomp_init() < 0) {
            free(keep_keys);
            free(set_pairs);
            return 1;
        }
    }

    if (sandbox_env_apply(clean_env, keep_keys, keep_count, set_pairs, set_count) < 0) {
        free(keep_keys);
        free(set_pairs);
        return 1;
    }

    free(keep_keys);
    free(set_pairs);

    /* security boundary: execvp transfers control to target command replacing current image */
    execvp(command_argv[0], command_argv);

    fprintf(stderr, "safe-agent: failed to execute '%s': %s\n",
            command_argv[0], strerror(errno));
    return (errno == ENOENT) ? 127 : 126;
}
