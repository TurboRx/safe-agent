#ifndef SANDBOX_H
#define SANDBOX_H

#include <stdbool.h>
#include <stddef.h>

struct sandbox_config {
    const char *allow_dir;
    bool block_net;
    char *const *command_argv;
};

int sandbox_landlock_init(const char *allow_dir);
int sandbox_seccomp_init(void);

int sandbox_env_apply(bool clean_env,
                      char *const *keep_keys,
                      size_t keep_count,
                      char *const *set_pairs,
                      size_t set_count);

#endif
