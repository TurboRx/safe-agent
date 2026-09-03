# safe-agent

`safe-agent` is a Linux security sandbox binary designed for constrained AI agent command execution using Landlock LSM and seccomp-bpf.

## Features

- **Filesystem Isolation (Landlock LSM)**: Restricts write, create, truncate, and unlink operations strictly to the directory passed via `--allow-dir`. Preserves read and execute access for core system paths (`/usr`, `/lib`, `/bin`, `/etc`).
- **Syscall Filtering (seccomp-bpf)**: When `--block-net` is enabled, installs a BPF filter to intercept and deny `socket`, `connect`, and `bind` syscalls, returning `EPERM`.
- **Privilege Boundary Enforcement**: Sets `PR_SET_NO_NEW_PRIVS` prior to enforcing sandbox rulesets and handing off execution via `execvp`.

## Requirements

- Linux kernel >= 5.13 with Landlock LSM enabled (`CONFIG_SECURITY_LANDLOCK=y`).
- C11 compiler (GCC or Clang).
- GNU Make.

## Build

```bash
make
```

Binary target: `safe-agent`.

To clean build artifacts:
```bash
make clean
```

## Usage

```bash
./safe-agent --allow-dir <path> [--block-net] -- <command> [args...]
```

### Options

- `--allow-dir <path>`: Directory hierarchy where write/create/truncate/unlink actions are permitted.
- `--block-net`: Blocks network socket creation, binding, and connection requests (returns `EPERM`).
- `--`: Separator preceding the command and arguments to execute.

### Examples

Execute a build script constrained to `/workspace`:
```bash
./safe-agent --allow-dir /workspace -- make test
```

Execute a command isolated from both external filesystems and network access:
```bash
./safe-agent --allow-dir /workspace --block-net -- python3 script.py
```

## Architecture

- `include/sandbox.h`: Interface definitions and configuration structures.
- `src/main.c`: CLI argument parsing, security boundary validation, and execution hand-off.
- `src/sandbox.c`: Landlock ABI version negotiation, bitmask fallback logic, ruleset assembly, and enforcement.
- `src/seccomp_filter.c`: BPF filter construction for network syscall denial.

## License

MIT
