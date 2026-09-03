#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "sandbox.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <linux/prctl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef LANDLOCK_CREATE_RULESET_VERSION
#define LANDLOCK_CREATE_RULESET_VERSION (1U << 0)
#endif

#ifndef LANDLOCK_RULE_PATH_BENEATH
#define LANDLOCK_RULE_PATH_BENEATH 1
#endif

#ifndef LANDLOCK_RULE_NET_PORT
#define LANDLOCK_RULE_NET_PORT 2
#endif

#ifndef LANDLOCK_ACCESS_FS_EXECUTE
#define LANDLOCK_ACCESS_FS_EXECUTE (1ULL << 0)
#define LANDLOCK_ACCESS_FS_WRITE_FILE (1ULL << 1)
#define LANDLOCK_ACCESS_FS_READ_FILE (1ULL << 2)
#define LANDLOCK_ACCESS_FS_READ_DIR (1ULL << 3)
#define LANDLOCK_ACCESS_FS_REMOVE_DIR (1ULL << 4)
#define LANDLOCK_ACCESS_FS_REMOVE_FILE (1ULL << 5)
#define LANDLOCK_ACCESS_FS_MAKE_CHAR (1ULL << 6)
#define LANDLOCK_ACCESS_FS_MAKE_DIR (1ULL << 7)
#define LANDLOCK_ACCESS_FS_MAKE_REG (1ULL << 8)
#define LANDLOCK_ACCESS_FS_MAKE_SOCK (1ULL << 9)
#define LANDLOCK_ACCESS_FS_MAKE_FIFO (1ULL << 10)
#define LANDLOCK_ACCESS_FS_MAKE_BLOCK (1ULL << 11)
#define LANDLOCK_ACCESS_FS_MAKE_SYM (1ULL << 12)
#endif

#ifndef LANDLOCK_ACCESS_FS_REFER
#define LANDLOCK_ACCESS_FS_REFER (1ULL << 13)
#endif

#ifndef LANDLOCK_ACCESS_FS_TRUNCATE
#define LANDLOCK_ACCESS_FS_TRUNCATE (1ULL << 14)
#endif

#ifndef LANDLOCK_ACCESS_NET_BIND_TCP
#define LANDLOCK_ACCESS_NET_BIND_TCP (1ULL << 0)
#endif

#ifndef LANDLOCK_ACCESS_NET_CONNECT_TCP
#define LANDLOCK_ACCESS_NET_CONNECT_TCP (1ULL << 1)
#endif

#ifndef __NR_landlock_create_ruleset
#define __NR_landlock_create_ruleset 444
#endif

#ifndef __NR_landlock_add_rule
#define __NR_landlock_add_rule 445
#endif

#ifndef __NR_landlock_restrict_self
#define __NR_landlock_restrict_self 446
#endif

static inline int sys_landlock_create_ruleset(const struct landlock_ruleset_attr *const attr,
                                              const size_t size, const uint32_t flags)
{
    return (int)syscall(__NR_landlock_create_ruleset, attr, size, flags);
}

static inline int sys_landlock_add_rule(const int ruleset_fd,
                                        const enum landlock_rule_type rule_type,
                                        const void *const rule_attr, const uint32_t flags)
{
    return (int)syscall(__NR_landlock_add_rule, ruleset_fd, rule_type, rule_attr, flags);
}

static inline int sys_landlock_restrict_self(const int ruleset_fd, const uint32_t flags)
{
    return (int)syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}

/* security boundary: handled access rights without an explicit allow rule are denied by default across the filesystem hierarchy */
#define ACCESS_FS_RO ( \
    LANDLOCK_ACCESS_FS_EXECUTE | \
    LANDLOCK_ACCESS_FS_READ_FILE | \
    LANDLOCK_ACCESS_FS_READ_DIR)

#define ACCESS_FS_RW ( \
    ACCESS_FS_RO | \
    LANDLOCK_ACCESS_FS_WRITE_FILE | \
    LANDLOCK_ACCESS_FS_REMOVE_DIR | \
    LANDLOCK_ACCESS_FS_REMOVE_FILE | \
    LANDLOCK_ACCESS_FS_MAKE_CHAR | \
    LANDLOCK_ACCESS_FS_MAKE_DIR | \
    LANDLOCK_ACCESS_FS_MAKE_REG | \
    LANDLOCK_ACCESS_FS_MAKE_SOCK | \
    LANDLOCK_ACCESS_FS_MAKE_FIFO | \
    LANDLOCK_ACCESS_FS_MAKE_BLOCK | \
    LANDLOCK_ACCESS_FS_MAKE_SYM | \
    LANDLOCK_ACCESS_FS_REFER | \
    LANDLOCK_ACCESS_FS_TRUNCATE)

static const char *const system_read_paths[] = {
    "/usr",
    "/lib",
    "/bin",
    "/etc",
    "/lib64",
    "/dev",
};

int sandbox_landlock_init_paths(char *const *allow_dirs,
                                size_t allow_dir_count,
                                char *const *ro_dirs,
                                size_t ro_dir_count)
{
    return sandbox_landlock_init_full(allow_dirs, allow_dir_count,
                                     ro_dirs, ro_dir_count,
                                     NULL, 0, NULL, 0);
}

int sandbox_landlock_init_full(char *const *allow_dirs,
                              size_t allow_dir_count,
                              char *const *ro_dirs,
                              size_t ro_dir_count,
                              const unsigned int *net_connect_ports,
                              size_t net_connect_count,
                              const unsigned int *net_bind_ports,
                              size_t net_bind_count)
{
    if (!allow_dirs || allow_dir_count == 0) {
        fprintf(stderr, "safe-agent: at least one allow directory is required\n");
        return -1;
    }

    /* kernel abi quirk: queries abi version; unsupported access bits cause sys_landlock_create_ruleset to fail with einval */
    int abi = sys_landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 0) {
        fprintf(stderr, "safe-agent: landlock abi query failed: %s\n", strerror(errno));
        return -1;
    }
    if (abi < 1) {
        fprintf(stderr, "safe-agent: landlock abi version %d unsupported\n", abi);
        return -1;
    }

    if ((net_connect_count > 0 || net_bind_count > 0) && abi < 4) {
        fprintf(stderr, "safe-agent: landlock network port filtering requires abi v4 or higher (kernel >= 6.5, detected v%d)\n", abi);
        return -1;
    }

    struct landlock_ruleset_attr ruleset_attr = {
        .handled_access_fs = ACCESS_FS_RW,
    };

    /* bitmask fallback: truncate requires abi v3; refer requires abi v2 */
    if (abi < 2) {
        /* kernel abi quirk: landlock_access_fs_refer requires abi v2; reparenting across directories is denied by default on v1 */
        ruleset_attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_REFER;
    }
    if (abi < 3) {
        /* kernel abi quirk: landlock_access_fs_truncate requires abi v3 */
        ruleset_attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_TRUNCATE;
    }

    if (abi >= 4 && (net_connect_count > 0 || net_bind_count > 0)) {
        /* kernel abi quirk: handled_access_net requires abi v4 or higher */
        /* security boundary: all unlisted tcp ports are denied by default once handled_access_net is set */
        ruleset_attr.handled_access_net = 0;
        if (net_connect_count > 0) {
            ruleset_attr.handled_access_net |= LANDLOCK_ACCESS_NET_CONNECT_TCP;
        }
        if (net_bind_count > 0) {
            ruleset_attr.handled_access_net |= LANDLOCK_ACCESS_NET_BIND_TCP;
        }
    }

    /* kernel abi quirk: size of handled_access_fs ensures compatibility across abi v1 through v5 kernels */
    size_t attr_size = (net_connect_count == 0 && net_bind_count == 0)
                           ? sizeof(ruleset_attr.handled_access_fs)
                           : sizeof(ruleset_attr);

    int ruleset_fd = sys_landlock_create_ruleset(&ruleset_attr, attr_size, 0);
    if (ruleset_fd < 0) {
        fprintf(stderr, "safe-agent: failed to create landlock ruleset: %s\n", strerror(errno));
        return -1;
    }

    for (size_t i = 0; i < allow_dir_count; i++) {
        if (!allow_dirs[i] || allow_dirs[i][0] == '\0') {
            fprintf(stderr, "safe-agent: allow directory path is invalid\n");
            close(ruleset_fd);
            return -1;
        }

        /* kernel abi quirk: parent_fd must refer to a directory opened with o_path | o_directory | o_cloexec */
        int allow_fd = open(allow_dirs[i], O_PATH | O_DIRECTORY | O_CLOEXEC);
        if (allow_fd < 0) {
            fprintf(stderr, "safe-agent: failed to open allow directory '%s': %s\n",
                    allow_dirs[i], strerror(errno));
            close(ruleset_fd);
            return -1;
        }

        /* security boundary: rule access rights must be a subset of ruleset handled_access_fs to avoid einval */
        struct landlock_path_beneath_attr allow_path_attr = {
            .parent_fd = allow_fd,
            .allowed_access = ACCESS_FS_RW & ruleset_attr.handled_access_fs,
        };

        if (sys_landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &allow_path_attr, 0) < 0) {
            fprintf(stderr, "safe-agent: failed to add landlock rule for allow directory '%s': %s\n",
                    allow_dirs[i], strerror(errno));
            close(allow_fd);
            close(ruleset_fd);
            return -1;
        }

        if (close(allow_fd) < 0) {
            fprintf(stderr, "safe-agent: failed to close allow directory fd: %s\n", strerror(errno));
            close(ruleset_fd);
            return -1;
        }
    }

    for (size_t i = 0; i < ro_dir_count; i++) {
        if (!ro_dirs[i] || ro_dirs[i][0] == '\0') {
            fprintf(stderr, "safe-agent: read-only directory path is invalid\n");
            close(ruleset_fd);
            return -1;
        }

        int ro_fd = open(ro_dirs[i], O_PATH | O_DIRECTORY | O_CLOEXEC);
        if (ro_fd < 0) {
            fprintf(stderr, "safe-agent: failed to open read-only directory '%s': %s\n",
                    ro_dirs[i], strerror(errno));
            close(ruleset_fd);
            return -1;
        }

        struct landlock_path_beneath_attr ro_path_attr = {
            .parent_fd = ro_fd,
            .allowed_access = ACCESS_FS_RO & ruleset_attr.handled_access_fs,
        };

        if (sys_landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &ro_path_attr, 0) < 0) {
            fprintf(stderr, "safe-agent: failed to add landlock rule for read-only directory '%s': %s\n",
                    ro_dirs[i], strerror(errno));
            close(ro_fd);
            close(ruleset_fd);
            return -1;
        }

        if (close(ro_fd) < 0) {
            fprintf(stderr, "safe-agent: failed to close read-only directory fd: %s\n", strerror(errno));
            close(ruleset_fd);
            return -1;
        }
    }

    for (size_t i = 0; i < sizeof(system_read_paths) / sizeof(system_read_paths[0]); i++) {
        int sys_fd = open(system_read_paths[i], O_PATH | O_DIRECTORY | O_CLOEXEC);
        if (sys_fd < 0) {
            if (errno == ENOENT) {
                continue;
            }
            fprintf(stderr, "safe-agent: failed to open system path '%s': %s\n",
                    system_read_paths[i], strerror(errno));
            close(ruleset_fd);
            return -1;
        }

        struct landlock_path_beneath_attr sys_path_attr = {
            .parent_fd = sys_fd,
            .allowed_access = ACCESS_FS_RO & ruleset_attr.handled_access_fs,
        };

        if (sys_landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &sys_path_attr, 0) < 0) {
            fprintf(stderr, "safe-agent: failed to add landlock rule for system path '%s': %s\n",
                    system_read_paths[i], strerror(errno));
            close(sys_fd);
            close(ruleset_fd);
            return -1;
        }

        if (close(sys_fd) < 0) {
            fprintf(stderr, "safe-agent: failed to close system path fd: %s\n", strerror(errno));
            close(ruleset_fd);
            return -1;
        }
    }

    for (size_t i = 0; i < net_connect_count; i++) {
        struct landlock_net_port_attr port_attr = {
            .allowed_access = LANDLOCK_ACCESS_NET_CONNECT_TCP,
            .port = net_connect_ports[i],
        };
        if (sys_landlock_add_rule(ruleset_fd, LANDLOCK_RULE_NET_PORT, &port_attr, 0) < 0) {
            fprintf(stderr, "safe-agent: failed to add connect rule for port %u: %s\n",
                    net_connect_ports[i], strerror(errno));
            close(ruleset_fd);
            return -1;
        }
    }

    for (size_t i = 0; i < net_bind_count; i++) {
        struct landlock_net_port_attr port_attr = {
            .allowed_access = LANDLOCK_ACCESS_NET_BIND_TCP,
            .port = net_bind_ports[i],
        };
        if (sys_landlock_add_rule(ruleset_fd, LANDLOCK_RULE_NET_PORT, &port_attr, 0) < 0) {
            fprintf(stderr, "safe-agent: failed to add bind rule for port %u: %s\n",
                    net_bind_ports[i], strerror(errno));
            close(ruleset_fd);
            return -1;
        }
    }

    /* security boundary: pr_set_no_new_privs is strictly required before landlock_restrict_self */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        fprintf(stderr, "safe-agent: prctl(PR_SET_NO_NEW_PRIVS) failed: %s\n", strerror(errno));
        close(ruleset_fd);
        return -1;
    }

    if (sys_landlock_restrict_self(ruleset_fd, 0) < 0) {
        fprintf(stderr, "safe-agent: failed to enforce landlock ruleset: %s\n", strerror(errno));
        close(ruleset_fd);
        return -1;
    }

    if (close(ruleset_fd) < 0) {
        fprintf(stderr, "safe-agent: failed to close ruleset fd: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

int sandbox_landlock_init(const char *allow_dir)
{
    char *dirs[1];
    dirs[0] = (char *)allow_dir;
    return sandbox_landlock_init_paths(dirs, 1, NULL, 0);
}
