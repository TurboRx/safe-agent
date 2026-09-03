#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "sandbox.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t g_timed_out = 0;
static volatile pid_t g_supervised_child = 0;

static void supervisor_signal_handler(int sig)
{
    if (sig == SIGALRM) {
        g_timed_out = 1;
    }
    if (g_supervised_child > 0) {
        /* security boundary: terminate full child process group to prevent orphaned background workers */
        kill(-g_supervised_child, SIGKILL);
        kill(g_supervised_child, SIGKILL);
    }
}

int sandbox_child_execute(const struct sandbox_exec_args *args)
{
    if (args->tmpfs_count > 0) {
        if (sandbox_mountns_apply(args->tmpfs_paths, args->tmpfs_count) < 0) {
            return 1;
        }
    }

    if (args->drop_net) {
        if (sandbox_netns_drop() < 0) {
            return 1;
        }
    }

    /* security boundary: pr_set_no_new_privs prevents execvp targets from gaining privileges */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        fprintf(stderr, "safe-agent: prctl(PR_SET_NO_NEW_PRIVS) failed: %s\n", strerror(errno));
        return 1;
    }

    if (sandbox_rlimits_apply(&args->rlimits) < 0) {
        return 1;
    }

    if (sandbox_landlock_init_full(args->allow_dirs, args->allow_dir_count,
                                  args->ro_dirs, args->ro_dir_count,
                                  args->net_connect_ports, args->net_connect_count,
                                  args->net_bind_ports, args->net_bind_count) < 0) {
        return 1;
    }

    if (args->block_net || args->block_tiocsti || args->harden_sys) {
        if (sandbox_seccomp_apply(args->block_net, args->block_tiocsti, args->harden_sys) < 0) {
            return 1;
        }
    }

    if (sandbox_env_apply(args->clean_env, args->keep_keys, args->keep_count,
                          args->set_pairs, args->set_count) < 0) {
        return 1;
    }

    /* security boundary: execvp transfers control to target command replacing current image */
    execvp(args->command_argv[0], args->command_argv);

    fprintf(stderr, "safe-agent: failed to execute '%s': %s\n",
            args->command_argv[0], strerror(errno));
    return (errno == ENOENT) ? 127 : 126;
}

int sandbox_supervisor_execute(unsigned int timeout_seconds,
                               const struct sandbox_exec_args *args)
{
    if (timeout_seconds == 0 && !args->new_pid && args->max_output_bytes == 0 && !args->audit_log_path && !args->cgroup_path) {
        /* security boundary: when no supervisor features are requested, execute directly */
        return sandbox_child_execute(args);
    }

    if (args->new_pid) {
        if (sandbox_pidns_unshare() < 0) {
            return 1;
        }
    }

    int pipe_out[2] = { -1, -1 };
    int pipe_err[2] = { -1, -1 };
    if (args->max_output_bytes > 0) {
        if (pipe2(pipe_out, O_CLOEXEC) < 0 || pipe2(pipe_err, O_CLOEXEC) < 0) {
            fprintf(stderr, "safe-agent: failed to create output quota pipes: %s\n", strerror(errno));
            if (pipe_out[0] >= 0) { close(pipe_out[0]); close(pipe_out[1]); }
            return 1;
        }
    }

    g_timed_out = 0;
    g_supervised_child = 0;

    struct sigaction sa = {
        .sa_handler = supervisor_signal_handler,
    };
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGALRM, &sa, NULL) < 0 ||
        sigaction(SIGINT, &sa, NULL) < 0 ||
        sigaction(SIGTERM, &sa, NULL) < 0) {
        fprintf(stderr, "safe-agent: failed to set up signal handlers: %s\n", strerror(errno));
        if (args->max_output_bytes > 0) {
            close(pipe_out[0]); close(pipe_out[1]);
            close(pipe_err[0]); close(pipe_err[1]);
        }
        return 1;
    }

    struct timespec ts_start;
    clock_gettime(CLOCK_MONOTONIC, &ts_start);

    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "safe-agent: fork failed: %s\n", strerror(errno));
        if (args->max_output_bytes > 0) {
            close(pipe_out[0]); close(pipe_out[1]);
            close(pipe_err[0]); close(pipe_err[1]);
        }
        return 1;
    }

    if (pid == 0) {
        /* security boundary: create new process group so kill targets full descendant tree */
        if (setpgid(0, 0) < 0) {
            fprintf(stderr, "safe-agent: setpgid failed: %s\n", strerror(errno));
            _exit(1);
        }

        /* security boundary: kill child if parent supervisor process terminates unexpectedly */
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) < 0) {
            fprintf(stderr, "safe-agent: prctl(PR_SET_PDEATHSIG) failed: %s\n", strerror(errno));
            _exit(1);
        }

        if (args->max_output_bytes > 0) {
            dup2(pipe_out[1], STDOUT_FILENO);
            dup2(pipe_err[1], STDERR_FILENO);
            close(pipe_out[0]); close(pipe_out[1]);
            close(pipe_err[0]); close(pipe_err[1]);
        }

        int child_res = sandbox_child_execute(args);
        _exit(child_res);
    }

    bool cgroup_created = false;
    if (args->cgroup_path) {
        if (sandbox_cgroup_setup(args->cgroup_path, &args->rlimits, pid, &cgroup_created) < 0) {
            kill(pid, SIGKILL);
            waitpid(pid, NULL, 0);
            return 1;
        }
    }

    g_supervised_child = pid;
    if (timeout_seconds > 0) {
        alarm(timeout_seconds);
    }

    bool quota_exceeded = false;
    if (args->max_output_bytes > 0) {
        close(pipe_out[1]);
        close(pipe_err[1]);

        size_t total_bytes = 0;
        struct pollfd pfds[2] = {
            { .fd = pipe_out[0], .events = POLLIN },
            { .fd = pipe_err[0], .events = POLLIN },
        };
        int open_pipes = 2;

        while (open_pipes > 0) {
            if (g_timed_out) {
                break;
            }
            int ret = poll(pfds, 2, -1);
            if (ret < 0) {
                if (errno == EINTR) continue;
                break;
            }

            for (int p = 0; p < 2; p++) {
                if (pfds[p].fd < 0) continue;

                if (pfds[p].revents & POLLIN) {
                    char buf[4096];
                    ssize_t n = read(pfds[p].fd, buf, sizeof(buf));
                    if (n > 0) {
                        int out_fd = (p == 0) ? STDOUT_FILENO : STDERR_FILENO;
                        size_t to_write = (size_t)n;
                        if (total_bytes + to_write > args->max_output_bytes) {
                            to_write = args->max_output_bytes - total_bytes;
                            quota_exceeded = true;
                        }
                        if (to_write > 0) {
                            ssize_t wr = write(out_fd, buf, to_write);
                            (void)wr;
                        }
                        total_bytes += (size_t)n;

                        if (total_bytes >= args->max_output_bytes) {
                            quota_exceeded = true;
                            kill(-pid, SIGKILL);
                            kill(pid, SIGKILL);
                            close(pipe_out[0]);
                            close(pipe_err[0]);
                            pfds[0].fd = -1;
                            pfds[1].fd = -1;
                            open_pipes = 0;
                            break;
                        }
                    } else if (n == 0) {
                        close(pfds[p].fd);
                        pfds[p].fd = -1;
                        open_pipes--;
                    }
                } else if (pfds[p].revents & (POLLHUP | POLLERR)) {
                    close(pfds[p].fd);
                    pfds[p].fd = -1;
                    open_pipes--;
                }
            }
        }
        if (pfds[0].fd >= 0) close(pfds[0].fd);
        if (pfds[1].fd >= 0) close(pfds[1].fd);
    }

    struct rusage ru = {0};
    int status = 0;
    while (wait4(pid, &status, 0, &ru) < 0) {
        if (errno == EINTR) {
            continue;
        }
        fprintf(stderr, "safe-agent: wait4 failed: %s\n", strerror(errno));
        return 1;
    }

    struct timespec ts_end;
    clock_gettime(CLOCK_MONOTONIC, &ts_end);
    double wall_ms = (double)(ts_end.tv_sec - ts_start.tv_sec) * 1000.0 +
                     (double)(ts_end.tv_nsec - ts_start.tv_nsec) / 1000000.0;

    if (timeout_seconds > 0) {
        alarm(0);
    }

    if (args->cgroup_path) {
        sandbox_cgroup_cleanup(args->cgroup_path, cgroup_created);
    }

    int exit_code = 1;
    int term_sig = 0;

    if (quota_exceeded) {
        exit_code = 125;
        fprintf(stderr, "safe-agent: command exceeded maximum output quota of %zu bytes\n",
                args->max_output_bytes);
    } else if (g_timed_out) {
        exit_code = 124;
        fprintf(stderr, "safe-agent: command timed out after %u second%s\n",
                timeout_seconds, (timeout_seconds == 1) ? "" : "s");
    } else if (WIFEXITED(status)) {
        exit_code = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        term_sig = WTERMSIG(status);
        exit_code = 128 + term_sig;
    }

    if (args->audit_log_path) {
        sandbox_audit_write(args->audit_log_path, args, exit_code, term_sig,
                            g_timed_out != 0, quota_exceeded, wall_ms, &ru);
    }

    return exit_code;
}
