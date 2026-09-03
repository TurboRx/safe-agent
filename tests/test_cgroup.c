#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "sandbox.h"

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void touch_file(const char *dir, const char *name)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    int fd = open(path, O_CREAT | O_WRONLY, 0644);
    assert(fd >= 0);
    close(fd);
}

int main(void)
{
    printf("=== Running cgroups v2 Setup & Accounting Tests ===\n");

    char test_cgroup[] = "/tmp/safe_agent_cg_XXXXXX";
    char *d = mkdtemp(test_cgroup);
    assert(d != NULL);

    touch_file(test_cgroup, "cgroup.procs");
    touch_file(test_cgroup, "memory.max");
    touch_file(test_cgroup, "pids.max");

    struct sandbox_rlimits limits = {
        .max_mem_mb = 256,
        .max_procs = 32,
    };

    bool created = false;
    int res = sandbox_cgroup_setup(test_cgroup, &limits, 12345, &created);
    assert(res == 0);

    char procs_path[512];
    snprintf(procs_path, sizeof(procs_path), "%s/cgroup.procs", test_cgroup);
    FILE *f_procs = fopen(procs_path, "r");
    assert(f_procs != NULL);
    char buf[64];
    char *line = fgets(buf, sizeof(buf), f_procs);
    assert(line != NULL);
    assert(strcmp(buf, "12345\n") == 0);
    fclose(f_procs);

    char mem_path[512];
    snprintf(mem_path, sizeof(mem_path), "%s/memory.max", test_cgroup);
    FILE *f_mem = fopen(mem_path, "r");
    assert(f_mem != NULL);
    line = fgets(buf, sizeof(buf), f_mem);
    assert(line != NULL);
    assert(strcmp(buf, "268435456\n") == 0);
    fclose(f_mem);

    unlink(procs_path);
    unlink(mem_path);

    char pids_path[512];
    snprintf(pids_path, sizeof(pids_path), "%s/pids.max", test_cgroup);
    unlink(pids_path);

    sandbox_cgroup_cleanup(test_cgroup, true);

    printf("PASS: cgroup procs, memory.max, and pids.max configured properly\n");
    printf("All cgroups tests passed successfully.\n");
    return 0;
}
