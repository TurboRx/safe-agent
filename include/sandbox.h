#ifndef SANDBOX_H
#define SANDBOX_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/resource.h>
#include <unistd.h>

struct sandbox_rlimits {
    unsigned long max_mem_mb;
    unsigned long max_cpu_sec;
    unsigned long max_procs;
    unsigned long max_files;
};

struct sandbox_exec_args {
    char *const *allow_dirs;
    size_t allow_dir_count;
    char *const *ro_dirs;
    size_t ro_dir_count;
    char *const *tmpfs_paths;
    size_t tmpfs_count;
    const unsigned int *net_connect_ports;
    size_t net_connect_count;
    const unsigned int *net_bind_ports;
    size_t net_bind_count;
    bool block_net;
    bool drop_net;
    bool block_tiocsti;
    bool harden_sys;
    bool new_pid;
    bool clean_env;
    char *const *keep_keys;
    size_t keep_count;
    char *const *set_pairs;
    size_t set_count;
    struct sandbox_rlimits rlimits;
    size_t max_output_bytes;
    const char *cgroup_path;
    const char *audit_log_path;
    char **command_argv;
};

int sandbox_landlock_init(const char *allow_dir);
int sandbox_landlock_init_paths(char *const *allow_dirs,
                                size_t allow_dir_count,
                                char *const *ro_dirs,
                                size_t ro_dir_count);
int sandbox_landlock_init_full(char *const *allow_dirs,
                              size_t allow_dir_count,
                              char *const *ro_dirs,
                              size_t ro_dir_count,
                              const unsigned int *net_connect_ports,
                              size_t net_connect_count,
                              const unsigned int *net_bind_ports,
                              size_t net_bind_count);

int sandbox_seccomp_apply(bool block_net, bool block_tiocsti, bool harden_sys);

int sandbox_netns_drop(void);
int sandbox_pidns_unshare(void);
int sandbox_mountns_apply(char *const *tmpfs_paths, size_t tmpfs_count);

int sandbox_cgroup_setup(const char *cgroup_path,
                         const struct sandbox_rlimits *limits,
                         pid_t pid,
                         bool *created_out);
int sandbox_cgroup_cleanup(const char *cgroup_path, bool was_created);

int sandbox_env_apply(bool clean_env,
                      char *const *keep_keys,
                      size_t keep_count,
                      char *const *set_pairs,
                      size_t set_count);

int sandbox_rlimits_apply(const struct sandbox_rlimits *limits);

int sandbox_audit_write(const char *path,
                        const struct sandbox_exec_args *args,
                        int exit_code,
                        int term_sig,
                        bool timed_out,
                        bool quota_exceeded,
                        double wall_ms,
                        const struct rusage *ru);

int sandbox_profile_expand(int argc, char **argv, int *out_argc, char ***out_argv);
void sandbox_profile_free(int expanded_argc, char **expanded_argv, char **orig_argv);

int sandbox_child_execute(const struct sandbox_exec_args *args);
int sandbox_supervisor_execute(unsigned int timeout_seconds,
                               const struct sandbox_exec_args *args);

#endif
