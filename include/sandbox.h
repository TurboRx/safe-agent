#ifndef SANDBOX_H
#define SANDBOX_H

#include <stdbool.h>

struct sandbox_config {
    const char *allow_dir;
    bool block_net;
    char *const *command_argv;
};

int sandbox_landlock_init(const char *allow_dir);
int sandbox_seccomp_init(void);

#endif
