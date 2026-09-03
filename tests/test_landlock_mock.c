#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "sandbox.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

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

static int g_mock_abi_version = 3;
static uint64_t g_last_handled_access_fs = 0;
static uint64_t g_last_handled_access_net = 0;
static size_t g_last_attr_size = 0;
static int g_add_rule_calls = 0;
static int g_restrict_self_calls = 0;

/* kernel abi quirk: intercepted syscall routing allows deterministic testing of kernel abi negotiation */
long syscall(long number, ...)
{
    va_list args;
    va_start(args, number);

    if (number == 444) {
        const struct landlock_ruleset_attr *attr = va_arg(args, const struct landlock_ruleset_attr *);
        size_t size = va_arg(args, size_t);
        uint32_t flags = va_arg(args, uint32_t);
        va_end(args);

        if (flags == 1) {
            if (g_mock_abi_version < 0) {
                errno = ENOSYS;
                return -1;
            }
            return g_mock_abi_version;
        }

        g_last_handled_access_fs = attr->handled_access_fs;
        g_last_handled_access_net = (size >= sizeof(struct landlock_ruleset_attr)) ? attr->handled_access_net : 0;
        g_last_attr_size = size;

        return open("/dev/null", O_RDONLY | O_CLOEXEC);
    }

    if (number == 445) {
        va_end(args);
        g_add_rule_calls++;
        return 0;
    }

    if (number == 446) {
        va_end(args);
        g_restrict_self_calls++;
        return 0;
    }

    va_end(args);
    errno = ENOSYS;
    return -1;
}

int main(void)
{
    printf("=== Running Landlock ABI & Bitmask Mock Tests ===\n");

    g_mock_abi_version = 1;
    g_last_handled_access_fs = 0;
    g_add_rule_calls = 0;
    g_restrict_self_calls = 0;
    int res1 = sandbox_landlock_init("/tmp");
    assert(res1 == 0);
    assert((g_last_handled_access_fs & LANDLOCK_ACCESS_FS_REFER) == 0);
    assert((g_last_handled_access_fs & LANDLOCK_ACCESS_FS_TRUNCATE) == 0);
    assert(g_last_attr_size == sizeof(uint64_t));
    assert(g_add_rule_calls > 0);
    assert(g_restrict_self_calls == 1);
    printf("PASS: ABI v1 masks out REFER and TRUNCATE, uses 8-byte attr_size\n");

    g_mock_abi_version = 2;
    g_last_handled_access_fs = 0;
    int res2 = sandbox_landlock_init("/tmp");
    assert(res2 == 0);
    assert((g_last_handled_access_fs & LANDLOCK_ACCESS_FS_REFER) != 0);
    assert((g_last_handled_access_fs & LANDLOCK_ACCESS_FS_TRUNCATE) == 0);
    assert(g_last_attr_size == sizeof(uint64_t));
    printf("PASS: ABI v2 retains REFER and masks out TRUNCATE\n");

    g_mock_abi_version = 3;
    g_last_handled_access_fs = 0;
    int res3 = sandbox_landlock_init("/tmp");
    assert(res3 == 0);
    assert((g_last_handled_access_fs & LANDLOCK_ACCESS_FS_REFER) != 0);
    assert((g_last_handled_access_fs & LANDLOCK_ACCESS_FS_TRUNCATE) != 0);
    assert(g_last_attr_size == sizeof(uint64_t));
    printf("PASS: ABI v3 retains both REFER and TRUNCATE\n");

    /* test multiple allow and ro directories */
    g_add_rule_calls = 0;
    char *allow_dirs[] = { "/tmp", "/var/tmp" };
    char *ro_dirs[] = { "/usr" };
    int res_multi = sandbox_landlock_init_paths(allow_dirs, 2, ro_dirs, 1);
    assert(res_multi == 0);
    assert(g_add_rule_calls >= 3);
    printf("PASS: Multiple allow and ro directories configured\n");

    /* test abi v4 network port filtering */
    g_mock_abi_version = 4;
    g_add_rule_calls = 0;
    unsigned int connect_ports[] = { 443, 80 };
    unsigned int bind_ports[] = { 8080 };
    int res_net = sandbox_landlock_init_full(allow_dirs, 2, ro_dirs, 1,
                                            connect_ports, 2,
                                            bind_ports, 1);
    assert(res_net == 0);
    assert((g_last_handled_access_net & LANDLOCK_ACCESS_NET_CONNECT_TCP) != 0);
    assert((g_last_handled_access_net & LANDLOCK_ACCESS_NET_BIND_TCP) != 0);
    printf("PASS: ABI v4 configures TCP connect and bind port rules\n");

    /* test abi v3 rejecting net port filtering */
    g_mock_abi_version = 3;
    int res_net_fail = sandbox_landlock_init_full(allow_dirs, 2, ro_dirs, 1,
                                                 connect_ports, 2,
                                                 bind_ports, 1);
    assert(res_net_fail == -1);
    printf("PASS: ABI v3 cleanly rejects network port filtering with diagnostic\n");

    g_mock_abi_version = 0;
    int res4 = sandbox_landlock_init("/tmp");
    assert(res4 == -1);
    printf("PASS: ABI version 0 returns error\n");

    g_mock_abi_version = -1;
    int res5 = sandbox_landlock_init("/tmp");
    assert(res5 == -1);
    printf("PASS: Landlock ENOSYS returns error\n");

    g_mock_abi_version = 3;
    int res6 = sandbox_landlock_init("/path/that/does/not/exist/987123");
    assert(res6 == -1);
    printf("PASS: Non-existent directory returns error\n");

    int res7 = sandbox_landlock_init("/etc/hosts");
    assert(res7 == -1);
    printf("PASS: Regular file passed as directory returns error\n");

    printf("All Landlock mock tests passed successfully.\n");
    return 0;
}
