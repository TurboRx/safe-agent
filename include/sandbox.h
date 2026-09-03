#ifndef SANDBOX_H
#define SANDBOX_H

#include <stdbool.h>
#include <stddef.h>

struct sandbox_rlimits {
    unsigned long max_mem_mb;
    unsigned long max_cpu_sec;
    unsigned long max_procs;
    unsigned long max_files;
};

struct sandbox_config {
    char *const *allow_dirs;
    size_t allow_dir_count;
    char *const *ro_dirs;
    size_t ro_dir_count;
    bool block_net;
    bool block_tiocsti;
    char *const *command_argv;
};

struct sandbox_exec_args {
    char *const *allow_dirs;
    size_t allow_dir_count;
    char *const *ro_dirs;
    size_t ro_dir_count;
    bool block_net;
    bool block_tiocsti;
    bool clean_env;
    char *const *keep_keys;
    size_t keep_count;
    char *const *set_pairs;
    size_t set_count;
    struct sandbox_rlimits rlimits;
    char **command_argv;
};

int sandbox_landlock_init(const char *allow_dir);
int sandbox_landlock_init_paths(char *const *allow_dirs,
                                size_t allow_dir_count,
                                char *const *ro_dirs,
                                size_t ro_dir_count);

int sandbox_seccomp_init(void);
int sandbox_seccomp_apply(bool block_net, bool block_tiocsti);

int sandbox_env_apply(bool clean_env,
                      char *const *keep_keys,
                      size_t keep_count,
                      char *const *set_pairs,
                      size_t set_count);

int sandbox_rlimits_apply(const struct sandbox_rlimits *limits);

int sandbox_child_execute(const struct sandbox_exec_args *args);
int sandbox_supervisor_execute(unsigned int timeout_seconds,
                               const struct sandbox_exec_args *args);

#endif
