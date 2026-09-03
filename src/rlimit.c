#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "sandbox.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>

int sandbox_rlimits_apply(const struct sandbox_rlimits *limits)
{
    if (!limits) {
        return 0;
    }

    if (limits->max_mem_mb > 0) {
        /* security boundary: prevent integer overflow on 32-bit and 64-bit systems */
        if (limits->max_mem_mb > ULONG_MAX / (1024UL * 1024UL)) {
            fprintf(stderr, "safe-agent: memory limit value exceeds system maximum\n");
            return -1;
        }

        struct rlimit rl;
        unsigned long bytes = limits->max_mem_mb * 1024UL * 1024UL;
        rl.rlim_cur = (rlim_t)bytes;
        rl.rlim_max = (rlim_t)bytes;
        if (setrlimit(RLIMIT_AS, &rl) < 0) {
            fprintf(stderr, "safe-agent: failed to set memory limit: %s\n", strerror(errno));
            return -1;
        }
    }

    if (limits->max_cpu_sec > 0) {
        struct rlimit rl;
        rl.rlim_cur = (rlim_t)limits->max_cpu_sec;
        rl.rlim_max = (rlim_t)limits->max_cpu_sec;
        if (setrlimit(RLIMIT_CPU, &rl) < 0) {
            fprintf(stderr, "safe-agent: failed to set cpu time limit: %s\n", strerror(errno));
            return -1;
        }
    }

    if (limits->max_procs > 0) {
        struct rlimit rl;
        rl.rlim_cur = (rlim_t)limits->max_procs;
        rl.rlim_max = (rlim_t)limits->max_procs;
        if (setrlimit(RLIMIT_NPROC, &rl) < 0) {
            fprintf(stderr, "safe-agent: failed to set max processes limit: %s\n", strerror(errno));
            return -1;
        }
    }

    if (limits->max_files > 0) {
        struct rlimit rl;
        rl.rlim_cur = (rlim_t)limits->max_files;
        rl.rlim_max = (rlim_t)limits->max_files;
        if (setrlimit(RLIMIT_NOFILE, &rl) < 0) {
            fprintf(stderr, "safe-agent: failed to set max file descriptors limit: %s\n", strerror(errno));
            return -1;
        }
    }

    return 0;
}
