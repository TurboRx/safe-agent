#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "sandbox.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

int sandbox_audit_write(const char *path,
                        const struct sandbox_exec_args *args,
                        int exit_code,
                        int term_sig,
                        bool timed_out,
                        bool quota_exceeded,
                        double wall_ms,
                        const struct rusage *ru)
{
    if (!path || path[0] == '\0') {
        return 0;
    }

    FILE *f = fopen(path, "w");
    if (!f) {
        fprintf(stderr, "safe-agent: failed to open audit log file '%s': %s\n", path, strerror(errno));
        return -1;
    }

    double user_cpu = (double)ru->ru_utime.tv_sec * 1000.0 + (double)ru->ru_utime.tv_usec / 1000.0;
    double sys_cpu = (double)ru->ru_stime.tv_sec * 1000.0 + (double)ru->ru_stime.tv_usec / 1000.0;

    fprintf(f, "{\n");
    fprintf(f, "  \"command\": \"%s\",\n", (args->command_argv && args->command_argv[0]) ? args->command_argv[0] : "");
    fprintf(f, "  \"exit_code\": %d,\n", exit_code);
    fprintf(f, "  \"term_signal\": %d,\n", term_sig);
    fprintf(f, "  \"timed_out\": %s,\n", timed_out ? "true" : "false");
    fprintf(f, "  \"quota_exceeded\": %s,\n", quota_exceeded ? "true" : "false");
    fprintf(f, "  \"elapsed_ms\": %.3f,\n", wall_ms);
    fprintf(f, "  \"rusage\": {\n");
    fprintf(f, "    \"user_cpu_ms\": %.3f,\n", user_cpu);
    fprintf(f, "    \"sys_cpu_ms\": %.3f,\n", sys_cpu);
    fprintf(f, "    \"max_rss_kb\": %ld,\n", ru->ru_maxrss);
    fprintf(f, "    \"min_flt\": %ld,\n", ru->ru_minflt);
    fprintf(f, "    \"maj_flt\": %ld,\n", ru->ru_majflt);
    fprintf(f, "    \"vol_csw\": %ld,\n", ru->ru_nvcsw);
    fprintf(f, "    \"invol_csw\": %ld\n", ru->ru_nivcsw);
    fprintf(f, "  },\n");
    fprintf(f, "  \"config\": {\n");
    fprintf(f, "    \"allow_dir_count\": %zu,\n", args->allow_dir_count);
    fprintf(f, "    \"ro_dir_count\": %zu,\n", args->ro_dir_count);
    fprintf(f, "    \"tmpfs_count\": %zu,\n", args->tmpfs_count);
    fprintf(f, "    \"block_net\": %s,\n", args->block_net ? "true" : "false");
    fprintf(f, "    \"drop_net\": %s,\n", args->drop_net ? "true" : "false");
    fprintf(f, "    \"new_pid\": %s,\n", args->new_pid ? "true" : "false");
    fprintf(f, "    \"harden_sys\": %s,\n", args->harden_sys ? "true" : "false");
    fprintf(f, "    \"block_tiocsti\": %s\n", args->block_tiocsti ? "true" : "false");
    fprintf(f, "  }\n");
    fprintf(f, "}\n");

    if (fclose(f) != 0) {
        fprintf(stderr, "safe-agent: failed to write audit log: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}
