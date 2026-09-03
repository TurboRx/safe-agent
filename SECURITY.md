# Security Policy

## Supported Versions

Only the latest commit on the `main` branch is actively supported with security updates.

| Version | Supported |
| --- | --- |
| main (`HEAD`) | Yes |
| older revisions | No |

---

## Threat Model & Security Boundaries

`safe-agent` enforces execution boundaries using Linux kernel security primitives:
- **Landlock LSM**: Enforces mandatory access controls on the filesystem and network sockets even if the process has discretionary access permissions.
- **seccomp-bpf**: Intercepts and denies prohibited system calls (`socket`, `connect`, `bind`, `ptrace`, `bpf`, `ioctl(TIOCSTI)`, etc.) at the kernel syscall boundary.
- **Namespaces**: Isolates network (`CLONE_NEWNET`), PID tables (`CLONE_NEWPID`), and mount trees (`CLONE_NEWNS`) in unprivileged user namespaces.
- **PR_SET_NO_NEW_PRIVS**: Guarantees child processes cannot elevate privileges via setuid or capabilities.

### Non-Goals / Out-of-Scope
- Kernel-level privilege escalation bugs or kernel 0-days (defenses assume an uncompromised Linux kernel).
- Exhaustion of memory or CPU beyond the constraints configured via `setrlimit` or cgroups v2.

---

## Reporting a Vulnerability

If you discover a security vulnerability or sandbox escape in `safe-agent`:

1. **Do not** open a public issue on GitHub.
2. Report the vulnerability privately via GitHub Security Advisories or by emailing the project maintainer.
3. Include detailed steps to reproduce the issue, including target kernel version, architecture, and command invocations.
4. Maintainers will acknowledge reports within 48 hours and work on a fix in private prior to public disclosure.
