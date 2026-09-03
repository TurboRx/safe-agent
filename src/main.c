#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "sandbox.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void print_usage(const char *prog_name)
{
    fprintf(stderr,
            "usage: %s --allow-dir <path> [--allow-dir <path>...] [--ro-dir <path>...] [--allow-net-connect <port>...] [--allow-net-bind <port>...] [--block-net] [--block-tiocsti] [--clean-env] [--env KEY=VAL] [--keep-env KEY] [--timeout <sec>] [--max-mem <mb>] [--max-cpu <sec>] [--max-procs <n>] [--max-files <n>] -- <command> [args...]\n",
            prog_name);
}

static int parse_ulong(const char *arg, unsigned long *out)
{
    char *endptr = NULL;
    errno = 0;
    long val = strtol(arg, &endptr, 10);
    if (errno != 0 || *endptr != '\0' || val <= 0) {
        return -1;
    }
    *out = (unsigned long)val;
    return 0;
}

static int parse_port(const char *arg, unsigned int *out)
{
    char *endptr = NULL;
    errno = 0;
    long val = strtol(arg, &endptr, 10);
    if (errno != 0 || *endptr != '\0' || val <= 0 || val > 65535) {
        return -1;
    }
    *out = (unsigned int)val;
    return 0;
}

int main(int argc, char **argv)
{
    /* security boundary: validate argument array against zero-length execution vulnerabilities */
    const char *prog_name = (argc > 0 && argv && argv[0]) ? argv[0] : "safe-agent";
    if (argc < 2) {
        print_usage(prog_name);
        return 1;
    }

    char **allow_dirs = NULL;
    size_t allow_dir_count = 0;
    size_t allow_dir_cap = 0;

    char **ro_dirs = NULL;
    size_t ro_dir_count = 0;
    size_t ro_dir_cap = 0;

    unsigned int *net_connect_ports = NULL;
    size_t net_connect_count = 0;
    size_t net_connect_cap = 0;

    unsigned int *net_bind_ports = NULL;
    size_t net_bind_count = 0;
    size_t net_bind_cap = 0;

    bool block_net = false;
    bool block_tiocsti = false;
    bool clean_env = false;
    unsigned int timeout_seconds = 0;
    struct sandbox_rlimits rlimits = {0};

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
            free(allow_dirs);
            free(ro_dirs);
            free(net_connect_ports);
            free(net_bind_ports);
            free(keep_keys);
            free(set_pairs);
            return 0;
        }
        if (strcmp(argv[i], "--allow-dir") == 0) {
            if (i + 1 >= argc || strncmp(argv[i + 1], "--", 2) == 0) {
                fprintf(stderr, "safe-agent: error: --allow-dir requires a path argument\n");
                print_usage(prog_name);
                free(allow_dirs);
                free(ro_dirs);
                free(net_connect_ports);
                free(net_bind_ports);
                free(keep_keys);
                free(set_pairs);
                return 1;
            }
            if (argv[i + 1][0] == '\0') {
                fprintf(stderr, "safe-agent: error: --allow-dir path must not be empty\n");
                print_usage(prog_name);
                free(allow_dirs);
                free(ro_dirs);
                free(net_connect_ports);
                free(net_bind_ports);
                free(keep_keys);
                free(set_pairs);
                return 1;
            }
            if (allow_dir_count == allow_dir_cap) {
                size_t new_cap = (allow_dir_cap == 0) ? 4 : allow_dir_cap * 2;
                char **tmp = realloc(allow_dirs, new_cap * sizeof(char *));
                if (!tmp) {
                    fprintf(stderr, "safe-agent: out of memory for allow dirs\n");
                    free(allow_dirs);
                    free(ro_dirs);
                    free(net_connect_ports);
                    free(net_bind_ports);
                    free(keep_keys);
                    free(set_pairs);
                    return 1;
                }
                allow_dirs = tmp;
                allow_dir_cap = new_cap;
            }
            allow_dirs[allow_dir_count++] = argv[i + 1];
            i += 2;
            continue;
        }
        if (strcmp(argv[i], "--ro-dir") == 0) {
            if (i + 1 >= argc || strncmp(argv[i + 1], "--", 2) == 0) {
                fprintf(stderr, "safe-agent: error: --ro-dir requires a path argument\n");
                print_usage(prog_name);
                free(allow_dirs);
                free(ro_dirs);
                free(net_connect_ports);
                free(net_bind_ports);
                free(keep_keys);
                free(set_pairs);
                return 1;
            }
            if (argv[i + 1][0] == '\0') {
                fprintf(stderr, "safe-agent: error: --ro-dir path must not be empty\n");
                print_usage(prog_name);
                free(allow_dirs);
                free(ro_dirs);
                free(net_connect_ports);
                free(net_bind_ports);
                free(keep_keys);
                free(set_pairs);
                return 1;
            }
            if (ro_dir_count == ro_dir_cap) {
                size_t new_cap = (ro_dir_cap == 0) ? 4 : ro_dir_cap * 2;
                char **tmp = realloc(ro_dirs, new_cap * sizeof(char *));
                if (!tmp) {
                    fprintf(stderr, "safe-agent: out of memory for ro dirs\n");
                    free(allow_dirs);
                    free(ro_dirs);
                    free(net_connect_ports);
                    free(net_bind_ports);
                    free(keep_keys);
                    free(set_pairs);
                    return 1;
                }
                ro_dirs = tmp;
                ro_dir_cap = new_cap;
            }
            ro_dirs[ro_dir_count++] = argv[i + 1];
            i += 2;
            continue;
        }
        if (strcmp(argv[i], "--allow-net-connect") == 0) {
            unsigned int port = 0;
            if (i + 1 >= argc || parse_port(argv[i + 1], &port) < 0) {
                fprintf(stderr, "safe-agent: error: --allow-net-connect requires a valid port (1-65535)\n");
                print_usage(prog_name);
                free(allow_dirs);
                free(ro_dirs);
                free(net_connect_ports);
                free(net_bind_ports);
                free(keep_keys);
                free(set_pairs);
                return 1;
            }
            if (net_connect_count == net_connect_cap) {
                size_t new_cap = (net_connect_cap == 0) ? 4 : net_connect_cap * 2;
                unsigned int *tmp = realloc(net_connect_ports, new_cap * sizeof(unsigned int));
                if (!tmp) {
                    fprintf(stderr, "safe-agent: out of memory for net connect ports\n");
                    free(allow_dirs);
                    free(ro_dirs);
                    free(net_connect_ports);
                    free(net_bind_ports);
                    free(keep_keys);
                    free(set_pairs);
                    return 1;
                }
                net_connect_ports = tmp;
                net_connect_cap = new_cap;
            }
            net_connect_ports[net_connect_count++] = port;
            i += 2;
            continue;
        }
        if (strcmp(argv[i], "--allow-net-bind") == 0) {
            unsigned int port = 0;
            if (i + 1 >= argc || parse_port(argv[i + 1], &port) < 0) {
                fprintf(stderr, "safe-agent: error: --allow-net-bind requires a valid port (1-65535)\n");
                print_usage(prog_name);
                free(allow_dirs);
                free(ro_dirs);
                free(net_connect_ports);
                free(net_bind_ports);
                free(keep_keys);
                free(set_pairs);
                return 1;
            }
            if (net_bind_count == net_bind_cap) {
                size_t new_cap = (net_bind_cap == 0) ? 4 : net_bind_cap * 2;
                unsigned int *tmp = realloc(net_bind_ports, new_cap * sizeof(unsigned int));
                if (!tmp) {
                    fprintf(stderr, "safe-agent: out of memory for net bind ports\n");
                    free(allow_dirs);
                    free(ro_dirs);
                    free(net_connect_ports);
                    free(net_bind_ports);
                    free(keep_keys);
                    free(set_pairs);
                    return 1;
                }
                net_bind_ports = tmp;
                net_bind_cap = new_cap;
            }
            net_bind_ports[net_bind_count++] = port;
            i += 2;
            continue;
        }
        if (strcmp(argv[i], "--block-net") == 0) {
            block_net = true;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--block-tiocsti") == 0) {
            block_tiocsti = true;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--clean-env") == 0) {
            clean_env = true;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--timeout") == 0) {
            if (i + 1 >= argc || strncmp(argv[i + 1], "--", 2) == 0) {
                fprintf(stderr, "safe-agent: error: --timeout requires a seconds argument\n");
                print_usage(prog_name);
                free(allow_dirs);
                free(ro_dirs);
                free(net_connect_ports);
                free(net_bind_ports);
                free(keep_keys);
                free(set_pairs);
                return 1;
            }
            char *endptr = NULL;
            long val = strtol(argv[i + 1], &endptr, 10);
            if (*endptr != '\0' || val <= 0 || val > 86400) {
                fprintf(stderr, "safe-agent: error: --timeout must be a positive integer between 1 and 86400\n");
                print_usage(prog_name);
                free(allow_dirs);
                free(ro_dirs);
                free(net_connect_ports);
                free(net_bind_ports);
                free(keep_keys);
                free(set_pairs);
                return 1;
            }
            timeout_seconds = (unsigned int)val;
            i += 2;
            continue;
        }
        if (strcmp(argv[i], "--max-mem") == 0) {
            if (i + 1 >= argc || parse_ulong(argv[i + 1], &rlimits.max_mem_mb) < 0) {
                fprintf(stderr, "safe-agent: error: --max-mem requires a positive integer (mb)\n");
                print_usage(prog_name);
                free(allow_dirs);
                free(ro_dirs);
                free(net_connect_ports);
                free(net_bind_ports);
                free(keep_keys);
                free(set_pairs);
                return 1;
            }
            i += 2;
            continue;
        }
        if (strcmp(argv[i], "--max-cpu") == 0) {
            if (i + 1 >= argc || parse_ulong(argv[i + 1], &rlimits.max_cpu_sec) < 0) {
                fprintf(stderr, "safe-agent: error: --max-cpu requires a positive integer (sec)\n");
                print_usage(prog_name);
                free(allow_dirs);
                free(ro_dirs);
                free(net_connect_ports);
                free(net_bind_ports);
                free(keep_keys);
                free(set_pairs);
                return 1;
            }
            i += 2;
            continue;
        }
        if (strcmp(argv[i], "--max-procs") == 0) {
            if (i + 1 >= argc || parse_ulong(argv[i + 1], &rlimits.max_procs) < 0) {
                fprintf(stderr, "safe-agent: error: --max-procs requires a positive integer\n");
                print_usage(prog_name);
                free(allow_dirs);
                free(ro_dirs);
                free(net_connect_ports);
                free(net_bind_ports);
                free(keep_keys);
                free(set_pairs);
                return 1;
            }
            i += 2;
            continue;
        }
        if (strcmp(argv[i], "--max-files") == 0) {
            if (i + 1 >= argc || parse_ulong(argv[i + 1], &rlimits.max_files) < 0) {
                fprintf(stderr, "safe-agent: error: --max-files requires a positive integer\n");
                print_usage(prog_name);
                free(allow_dirs);
                free(ro_dirs);
                free(net_connect_ports);
                free(net_bind_ports);
                free(keep_keys);
                free(set_pairs);
                return 1;
            }
            i += 2;
            continue;
        }
        if (strcmp(argv[i], "--env") == 0) {
            if (i + 1 >= argc || strcmp(argv[i + 1], "--") == 0) {
                fprintf(stderr, "safe-agent: error: --env requires a KEY=VAL argument\n");
                print_usage(prog_name);
                free(allow_dirs);
                free(ro_dirs);
                free(net_connect_ports);
                free(net_bind_ports);
                free(keep_keys);
                free(set_pairs);
                return 1;
            }
            const char *eq = strchr(argv[i + 1], '=');
            if (!eq || eq == argv[i + 1]) {
                fprintf(stderr, "safe-agent: error: --env requires format KEY=VAL with non-empty KEY\n");
                print_usage(prog_name);
                free(allow_dirs);
                free(ro_dirs);
                free(net_connect_ports);
                free(net_bind_ports);
                free(keep_keys);
                free(set_pairs);
                return 1;
            }
            if (set_count == set_cap) {
                size_t new_cap = (set_cap == 0) ? 4 : set_cap * 2;
                char **tmp = realloc(set_pairs, new_cap * sizeof(char *));
                if (!tmp) {
                    fprintf(stderr, "safe-agent: out of memory for env pairs\n");
                    free(allow_dirs);
                    free(ro_dirs);
                    free(net_connect_ports);
                    free(net_bind_ports);
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
                free(allow_dirs);
                free(ro_dirs);
                free(net_connect_ports);
                free(net_bind_ports);
                free(keep_keys);
                free(set_pairs);
                return 1;
            }
            if (argv[i + 1][0] == '\0' || strchr(argv[i + 1], '=')) {
                fprintf(stderr, "safe-agent: error: --keep-env requires a valid variable name\n");
                print_usage(prog_name);
                free(allow_dirs);
                free(ro_dirs);
                free(net_connect_ports);
                free(net_bind_ports);
                free(keep_keys);
                free(set_pairs);
                return 1;
            }
            if (keep_count == keep_cap) {
                size_t new_cap = (keep_cap == 0) ? 4 : keep_cap * 2;
                char **tmp = realloc(keep_keys, new_cap * sizeof(char *));
                if (!tmp) {
                    fprintf(stderr, "safe-agent: out of memory for keep env\n");
                    free(allow_dirs);
                    free(ro_dirs);
                    free(net_connect_ports);
                    free(net_bind_ports);
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
        free(allow_dirs);
        free(ro_dirs);
        free(net_connect_ports);
        free(net_bind_ports);
        free(keep_keys);
        free(set_pairs);
        return 1;
    }

    if (allow_dir_count == 0) {
        fprintf(stderr, "safe-agent: error: missing required option --allow-dir\n");
        print_usage(prog_name);
        free(allow_dirs);
        free(ro_dirs);
        free(net_connect_ports);
        free(net_bind_ports);
        free(keep_keys);
        free(set_pairs);
        return 1;
    }

    if (!command_argv || !command_argv[0] || command_argv[0][0] == '\0') {
        fprintf(stderr, "safe-agent: error: missing command after '--'\n");
        print_usage(prog_name);
        free(allow_dirs);
        free(ro_dirs);
        free(net_connect_ports);
        free(net_bind_ports);
        free(keep_keys);
        free(set_pairs);
        return 1;
    }

    struct sandbox_exec_args exec_args = {
        .allow_dirs = allow_dirs,
        .allow_dir_count = allow_dir_count,
        .ro_dirs = ro_dirs,
        .ro_dir_count = ro_dir_count,
        .net_connect_ports = net_connect_ports,
        .net_connect_count = net_connect_count,
        .net_bind_ports = net_bind_ports,
        .net_bind_count = net_bind_count,
        .block_net = block_net,
        .block_tiocsti = block_tiocsti,
        .clean_env = clean_env,
        .keep_keys = keep_keys,
        .keep_count = keep_count,
        .set_pairs = set_pairs,
        .set_count = set_count,
        .rlimits = rlimits,
        .command_argv = command_argv,
    };

    int exit_code = sandbox_supervisor_execute(timeout_seconds, &exec_args);

    free(allow_dirs);
    free(ro_dirs);
    free(net_connect_ports);
    free(net_bind_ports);
    free(keep_keys);
    free(set_pairs);

    return exit_code;
}
