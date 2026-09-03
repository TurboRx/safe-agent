#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "sandbox.h"

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int write_file(const char *path, const char *data, size_t len)
{
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    ssize_t written = write(fd, data, len);
    close(fd);
    return (written == (ssize_t)len) ? 0 : -1;
}

int sandbox_netns_drop(void)
{
    /* security boundary: direct netns unshare succeeds when running as root or with cap_sys_admin */
    if (unshare(CLONE_NEWNET) == 0) {
        return 0;
    }

    uid_t uid = getuid();
    gid_t gid = getgid();

    /* security boundary: unprivileged netns creation requires user namespace */
    if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) {
        fprintf(stderr, "safe-agent: failed to unshare network namespace: %s\n", strerror(errno));
        return -1;
    }

    /* kernel abi quirk: setgroups must be set to deny before unprivileged gid_map can be written */
    if (write_file("/proc/self/setgroups", "deny", 4) < 0) {
        fprintf(stderr, "safe-agent: failed to write /proc/self/setgroups: %s\n", strerror(errno));
        return -1;
    }

    char map_buf[64];
    int len = snprintf(map_buf, sizeof(map_buf), "%u %u 1\n", (unsigned int)uid, (unsigned int)uid);
    if (len <= 0 || write_file("/proc/self/uid_map", map_buf, (size_t)len) < 0) {
        fprintf(stderr, "safe-agent: failed to write /proc/self/uid_map: %s\n", strerror(errno));
        return -1;
    }

    len = snprintf(map_buf, sizeof(map_buf), "%u %u 1\n", (unsigned int)gid, (unsigned int)gid);
    if (len <= 0 || write_file("/proc/self/gid_map", map_buf, (size_t)len) < 0) {
        fprintf(stderr, "safe-agent: failed to write /proc/self/gid_map: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}
