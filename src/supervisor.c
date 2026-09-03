#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "sandbox.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/wait.h>
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

    if (args->block_net || args->block_tiocsti) {
        if (sandbox_seccomp_apply(args->block_net, args->block_tiocsti) < 0) {
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
    if (timeout_seconds == 0) {
        /* security boundary: when no timeout is set, execute directly without supervisor overhead */
        return sandbox_child_execute(args);
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
        return 1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "safe-agent: fork failed: %s\n", strerror(errno));
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

        int child_res = sandbox_child_execute(args);
        _exit(child_res);
    }

    g_supervised_child = pid;
    alarm(timeout_seconds);

    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno == EINTR) {
            continue;
        }
        fprintf(stderr, "safe-agent: waitpid failed: %s\n", strerror(errno));
        return 1;
    }

    alarm(0);

    if (g_timed_out) {
        fprintf(stderr, "safe-agent: command timed out after %u second%s\n",
                timeout_seconds, (timeout_seconds == 1) ? "" : "s");
        return 124;
    }

    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
        return 128 + WTERMSIG(status);
    }

    return 1;
}
