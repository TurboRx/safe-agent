#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "sandbox.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int write_cgroup_file(const char *dir, const char *file, const char *val)
{
    char path[512];
    int len = snprintf(path, sizeof(path), "%s/%s", dir, file);
    if (len <= 0 || (size_t)len >= sizeof(path)) {
        return -1;
    }

    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }

    size_t val_len = strlen(val);
    ssize_t written = write(fd, val, val_len);
    close(fd);
    return (written == (ssize_t)val_len) ? 0 : -1;
}

int sandbox_cgroup_setup(const char *cgroup_path,
                         const struct sandbox_rlimits *limits,
                         pid_t pid,
                         bool *created_out)
{
    if (!cgroup_path || cgroup_path[0] == '\0') {
        if (created_out) *created_out = false;
        return 0;
    }

    bool created = false;
    if (mkdir(cgroup_path, 0755) == 0) {
        created = true;
    } else if (errno != EEXIST) {
        fprintf(stderr, "safe-agent: failed to create cgroup directory '%s': %s\n",
                cgroup_path, strerror(errno));
        return -1;
    }

    if (created_out) {
        *created_out = created;
    }

    char pid_buf[32];
    snprintf(pid_buf, sizeof(pid_buf), "%d\n", pid);
    if (write_cgroup_file(cgroup_path, "cgroup.procs", pid_buf) < 0) {
        fprintf(stderr, "safe-agent: failed to attach pid %d to cgroup '%s': %s\n",
                pid, cgroup_path, strerror(errno));
        if (created) {
            rmdir(cgroup_path);
        }
        return -1;
    }

    if (limits && limits->max_mem_mb > 0) {
        if (limits->max_mem_mb > ULONG_MAX / (1024UL * 1024UL)) {
            fprintf(stderr, "safe-agent: max memory value exceeds addressable range\n");
            return -1;
        }
        char mem_buf[64];
        unsigned long bytes = limits->max_mem_mb * 1024UL * 1024UL;
        snprintf(mem_buf, sizeof(mem_buf), "%lu\n", bytes);
        write_cgroup_file(cgroup_path, "memory.max", mem_buf);
    }

    if (limits && limits->max_procs > 0) {
        char procs_buf[32];
        snprintf(procs_buf, sizeof(procs_buf), "%lu\n", limits->max_procs);
        write_cgroup_file(cgroup_path, "pids.max", procs_buf);
    }

    return 0;
}

int sandbox_cgroup_cleanup(const char *cgroup_path, bool was_created)
{
    if (!cgroup_path || !was_created) {
        return 0;
    }
    return rmdir(cgroup_path);
}
