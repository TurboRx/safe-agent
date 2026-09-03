# Contributing to safe-agent

Thank you for your interest in contributing to `safe-agent`. As a security-focused binary designed to isolate autonomous AI agent processes on Linux, correctness, defense-in-depth, and strict kernel-level error handling are paramount.

---

## Development Prerequisites

- Linux system with kernel >= 5.13 (kernel >= 6.5 recommended for TCP port filtering).
- C11-compliant compiler: GCC 9+ or Clang 10+.
- GNU Make.
- Python 3 (for test assertion utilities and linters).
- `git`.

---

## Repository Architecture

The codebase follows a modular design where each security primitive is isolated into its own compilation unit:

| Source File | Responsibility |
| --- | --- |
| `src/main.c` | CLI argument parsing, security boundary verification, argument validation. |
| `src/sandbox.c` | Landlock LSM ABI version negotiation (v1–v5), bitmask fallback, and filesystem/network rule registration. |
| `src/seccomp_filter.c` | BPF filter generation for network syscall denial, high-risk syscall hardening (`--harden-sys`), and terminal injection defenses. |
| `src/supervisor.c` | Non-blocking process supervisor, timeout enforcement, signal propagation, and stream quota monitoring (`poll`). |
| `src/env.c` | Secure environment clearing and selective variable retention/injection. |
| `src/rlimit.c` | POSIX resource limit enforcement (`RLIMIT_AS`, `RLIMIT_CPU`, `RLIMIT_NPROC`, `RLIMIT_NOFILE`). |
| `src/netns.c` | Unprivileged network namespace isolation (`CLONE_NEWUSER \| CLONE_NEWNET`). |
| `src/pidns.c` | Unprivileged PID namespace isolation (`CLONE_NEWUSER \| CLONE_NEWPID`). |
| `src/mountns.c` | Unprivileged mount namespace creation and RAM-backed ephemeral scratch filesystem (`tmpfs`) mounting. |
| `src/audit.c` | High-resolution wall-clock duration measurement and structured JSON `rusage` telemetry serialization. |
| `src/profile.c` | Declarative INI/conf policy profile parsing and argument stream expansion. |
| `src/cgroup.c` | Linux cgroups v2 controller configuration and process attachment (`memory.max`, `pids.max`). |
| `include/sandbox.h` | Shared data types, structures, and public API prototypes. |
| `tests/` | Automated test suite covering unit behavior, CLI edge cases, and mock kernel ABI negotiation. |

---

## Code Standards & Guidelines

All contributions must strictly adhere to the following conventions:

### 1. Language & Compiler Standards
- Write clean, portable C11 code (`-std=c11`).
- Zero compiler warnings under `-Wall -Wextra -pedantic -O2`.
- Avoid non-portable glibc-specific extensions unless guarded under `#ifndef _GNU_SOURCE` and standard feature test macros.

### 2. Syscall & Error Handling
- Never ignore return codes from POSIX or Linux syscalls (`open`, `close`, `read`, `write`, `mount`, `unshare`, `prctl`, `setrlimit`, `fork`, `execvp`, `poll`, etc.).
- On failure, always print a diagnostic to `stderr` prefixed with `safe-agent: ` and format the active `strerror(errno)`.
- Use `_exit()` rather than `exit()` in forked child processes before `execvp` to prevent flushing or executing parent atexit handlers.

### 3. Comment Rules
- **Strictly lowercase**: All code comments across C source, headers, Makefiles, and shell scripts must use strictly lowercase characters (enforced by automated repository linting).
- **Zero redundant comments**: Never write comments explaining obvious C syntax, standard library functions, or routine control flow.
- **Retain only critical developer comments**: Document non-obvious kernel ABI quirks, bitmask fallback logic, and security boundary guarantees.

### 4. Commit Messages
- Use standard, clear imperative commit messages (e.g. `Add ephemeral in-memory tmpfs mount isolation via --tmpfs`).
- **Do not** use conventional commit prefixes (e.g., avoid `feat:`, `fix:`, `chore:`, `refactor:`).
- **Do not** use the word `patch` in commit messages.

---

## Build & Test Workflow

### Building
```bash
make
```

### Running the Test Suite
```bash
make test
```

### Sanitizer Verification
All changes must pass cleanly under AddressSanitizer (ASan) and UndefinedBehaviorSanitizer (UBSan):
```bash
make clean
make CFLAGS="-Wall -Wextra -pedantic -std=c11 -O2 -fsanitize=address,undefined" test
```

### Automated Comment Linting
Verify that all code comments comply with the lowercase rule:
```bash
python3 -c "
import re, glob
for filepath in sorted(glob.glob('**/*', recursive=True)):
    if filepath.endswith(('.c', '.h', 'Makefile', '.sh')):
        with open(filepath) as f:
            content = f.read()
        comments = re.findall(r'#.*?$', content, re.MULTILINE) if filepath.endswith(('.sh', 'Makefile')) else re.findall(r'/\*.*?\*/|//.*?$', content, re.MULTILINE | re.DOTALL)
        for c in comments:
            if not c.startswith('#!/usr/bin/env') and re.search(r'[A-Z]', c):
                print(f'LINT FAIL: {filepath}: {c}')
"
```

---

## Pull Request Checklist

Before submitting a pull request, ensure:
1. `make clean && make test` passes without errors.
2. Sanitizers (`-fsanitize=address,undefined`) report zero memory leaks or undefined behaviors.
3. Every new CLI flag or configuration feature includes corresponding test cases in `tests/test_cli.sh` and dedicated C test binaries in `tests/`.
4. The comment linter reports zero uppercase comment violations.
5. Commits are descriptive, use normal formatting without conventional prefixes, and avoid the word `patch`.
