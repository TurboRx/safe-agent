# safe-agent

`safe-agent` is a Linux security sandbox binary designed for constrained AI agent command execution using Landlock LSM, seccomp-bpf, resource quotas, and unprivileged namespaces.

## Features

- **Filesystem Isolation (Landlock LSM)**: Restricts write, create, truncate, and unlink operations strictly to directories passed via `--allow-dir`. Supports multiple `--allow-dir` paths and read-only directory paths via `--ro-dir`. Preserves read and execute access for system libraries and binaries (`/usr`, `/lib`, `/bin`, `/etc`).
- **Syscall Filtering (seccomp-bpf)**:
  - When `--block-net` is enabled, installs a BPF filter intercepting and denying `socket`, `connect`, and `bind` syscalls with `EPERM`.
  - When `--block-tiocsti` is enabled, traps `TIOCSTI` and `TIOCLINUX` `ioctl` commands to prevent terminal input injection sandbox escapes.
  - Validates system architecture (x86_64, aarch64, arm, i386, riscv64) and blocks x32 ABI evasion on x86_64.
- **Port-Level TCP Filtering (Landlock ABI v4+)**: Allows fine-grained outbound TCP connections via `--allow-net-connect <port>` and local socket binding via `--allow-net-bind <port>`. Denies all unlisted TCP ports by default.
- **Network Namespace Isolation**: `--drop-net` creates an unprivileged network namespace via `unshare(CLONE_NEWUSER | CLONE_NEWNET)`, isolating the command in a network stack with no interfaces.
- **Environment Sanitization**: `--clean-env` scrubs host environment variables, restoring a deterministic baseline `PATH=/usr/bin:/bin`. Specific variables can be preserved via `--keep-env KEY` or injected via `--env KEY=VAL`.
- **Process Supervision & Timeouts**: `--timeout <sec>` forks a supervisor process that monitors the execution tree, terminates the child process group via `SIGKILL` upon expiry, and exits with code 124.
- **Resource Quotas (`setrlimit`)**: Enforces memory limits (`--max-mem <mb>`), CPU execution time (`--max-cpu <sec>`), maximum process/thread count (`--max-procs <n>`), and open file limits (`--max-files <n>`).
- **Privilege Boundary Enforcement**: Sets `PR_SET_NO_NEW_PRIVS` prior to applying filters and transferring control via `execvp`.

## Requirements

- Linux kernel >= 5.13 for Landlock filesystem isolation (kernel >= 6.5 for TCP port filtering).
- C11 compiler (GCC or Clang).
- GNU Make.

## Build

```bash
make
```

Binary target: `safe-agent`.

To run the automated test suite:
```bash
make test
```

To clean build artifacts:
```bash
make clean
```

## Usage

```bash
./safe-agent --allow-dir <path> [options] -- <command> [args...]
```

### Options

| Option | Description |
| --- | --- |
| `--allow-dir <path>` | Writable directory hierarchy (can be specified multiple times). |
| `--ro-dir <path>` | Read-only directory hierarchy (can be specified multiple times). |
| `--allow-net-connect <port>` | Allow outbound TCP connection to port (Landlock ABI v4+). |
| `--allow-net-bind <port>` | Allow local TCP bind to port (Landlock ABI v4+). |
| `--block-net` | Block socket creation, bind, and connect via seccomp-bpf. |
| `--drop-net` | Unshare network namespace to an isolated stack with no network interfaces. |
| `--block-tiocsti` | Block `TIOCSTI` and `TIOCLINUX` terminal injection `ioctl` calls. |
| `--clean-env` | Clear all environment variables before running command. |
| `--env KEY=VAL` | Set environment variable inside sandbox (can be specified multiple times). |
| `--keep-env KEY` | Preserve specific host environment variable when `--clean-env` is active. |
| `--timeout <sec>` | Kill command process group if execution exceeds specified seconds. |
| `--max-mem <mb>` | Limit virtual memory address space (`RLIMIT_AS`) in megabytes. |
| `--max-cpu <sec>` | Limit CPU process time (`RLIMIT_CPU`) in seconds. |
| `--max-procs <n>` | Limit process and thread count (`RLIMIT_NPROC`). |
| `--max-files <n>` | Limit maximum open file descriptors (`RLIMIT_NOFILE`). |
| `--` | Separator preceding target command and arguments. |

### Examples

Run a test suite with filesystem writes restricted to `/workspace` and host environment scrubbed:
```bash
./safe-agent --allow-dir /workspace --clean-env --keep-env PATH -- make test
```

Execute an AI agent task with network completely dropped and a 30-second timeout:
```bash
./safe-agent --allow-dir /workspace --drop-net --timeout 30 -- python3 agent_task.py
```

Constrain an untrusted build process with resource limits and terminal injection protection:
```bash
./safe-agent --allow-dir /workspace --ro-dir /opt/toolchain --max-mem 2048 --max-cpu 60 --max-procs 64 --block-tiocsti -- ./build.sh
```

Allow outbound network access strictly to HTTPS (port 443) and HTTP (port 80) on Landlock ABI v4+ kernels:
```bash
./safe-agent --allow-dir /workspace --allow-net-connect 443 --allow-net-connect 80 -- curl https://example.com
```

## Architecture

- `include/sandbox.h`: Interface definitions and configuration structures.
- `src/main.c`: CLI argument parsing, security boundary validation, and supervisor orchestration.
- `src/sandbox.c`: Landlock ABI version negotiation, bitmask fallback logic, and network port filtering.
- `src/seccomp_filter.c`: BPF filter construction for network syscall denial and terminal injection defense.
- `src/env.c`: Environment sanitization and variable preservation logic.
- `src/supervisor.c`: Process supervision, process group termination, and timeout enforcement.
- `src/rlimit.c`: Resource quota enforcement via `setrlimit`.
- `src/netns.c`: Unprivileged network namespace isolation via `unshare(CLONE_NEWUSER | CLONE_NEWNET)`.
- `tests/`: Automated test suite covering CLI validation, seccomp filters, Landlock mock syscall routing, environment sanitization, process supervision, resource limits, and network namespaces.

## License

MIT
