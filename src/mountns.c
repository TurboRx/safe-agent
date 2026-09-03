#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "sandbox.h"

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
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

int sandbox_mountns_apply(char *const *tmpfs_paths, size_t tmpfs_count)
{
    if (!tmpfs_paths || tmpfs_count == 0) {
        return 0;
    }

    /* security boundary: unshare mount namespace directly if privileged or user namespace active */
    if (unshare(CLONE_NEWNS) < 0) {
        uid_t uid = getuid();
        gid_t gid = getgid();

        if (unshare(CLONE_NEWUSER | CLONE_NEWNS) < 0) {
            fprintf(stderr, "safe-agent: failed to unshare mount namespace: %s\n", strerror(errno));
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
    }

    /* security boundary: convert host mounts to private to prevent leakage across namespaces */
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0) {
        fprintf(stderr, "safe-agent: failed to set mount propagation private: %s\n", strerror(errno));
        return -1;
    }

    for (size_t i = 0; i < tmpfs_count; i++) {
        const char *target = tmpfs_paths[i];
        if (!target || target[0] == '\0') {
            fprintf(stderr, "safe-agent: invalid tmpfs target path\n");
            return -1;
        }

        struct stat st;
        if (stat(target, &st) < 0 || !S_ISDIR(st.st_mode)) {
            fprintf(stderr, "safe-agent: tmpfs target '%s' must be an existing directory: %s\n",
                    target, strerror(errno));
            return -1;
        }

        /* security boundary: mount ephemeral in-memory tmpfs with nosuid and nodev */
        if (mount("tmpfs", target, "tmpfs", MS_NOSUID | MS_NODEV, "size=64M,mode=1777") < 0) {
            fprintf(stderr, "safe-agent: failed to mount tmpfs at '%s': %s\n", target, strerror(errno));
            return -1;
        }
    }

    return 0;
}
