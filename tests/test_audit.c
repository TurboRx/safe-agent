#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "sandbox.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void)
{
    printf("=== Running Telemetry & Audit Log Tests ===\n");

    char log_path[] = "/tmp/safe_agent_audit_XXXXXX.json";
    int fd = mkstemps(log_path, 5);
    assert(fd >= 0);
    close(fd);

    char *dirs[] = { "/tmp" };
    char *cmd[] = { "/bin/true", NULL };
    struct sandbox_exec_args args = {
        .allow_dirs = dirs,
        .allow_dir_count = 1,
        .ro_dirs = NULL,
        .ro_dir_count = 0,
        .tmpfs_paths = NULL,
        .tmpfs_count = 0,
        .net_connect_ports = NULL,
        .net_connect_count = 0,
        .net_bind_ports = NULL,
        .net_bind_count = 0,
        .block_net = false,
        .drop_net = false,
        .block_tiocsti = false,
        .harden_sys = false,
        .new_pid = false,
        .clean_env = false,
        .keep_keys = NULL,
        .keep_count = 0,
        .set_pairs = NULL,
        .set_count = 0,
        .rlimits = {0},
        .max_output_bytes = 0,
        .audit_log_path = log_path,
        .command_argv = cmd,
    };

    struct rusage ru = {0};
    ru.ru_maxrss = 4096;
    ru.ru_minflt = 12;

    int res = sandbox_audit_write(log_path, &args, 0, 0, false, false, 4.5, &ru);
    assert(res == 0);

    FILE *f = fopen(log_path, "r");
    assert(f != NULL);

    char buf[2048];
    size_t bytes = fread(buf, 1, sizeof(buf) - 1, f);
    assert(bytes > 0);
    buf[bytes] = '\0';
    fclose(f);
    unlink(log_path);

    assert(strstr(buf, "\"command\": \"/bin/true\"") != NULL);
    assert(strstr(buf, "\"exit_code\": 0") != NULL);
    assert(strstr(buf, "\"max_rss_kb\": 4096") != NULL);
    assert(strstr(buf, "\"min_flt\": 12") != NULL);
    assert(strstr(buf, "\"allow_dir_count\": 1") != NULL);

    printf("PASS: Structured telemetry JSON written with accurate rusage and configuration\n");
    printf("All telemetry audit tests passed successfully.\n");
    return 0;
}
