#!/usr/bin/env bash
set -euo pipefail

BIN="./safe-agent"
PASS=0
FAIL=0

assert_exit() {
    local expected="$1"
    shift
    local desc="$1"
    shift
    set +e
    "$@" >/dev/null 2>&1
    local actual="$?"
    set -e
    if [ "$actual" -eq "$expected" ]; then
        echo "PASS: $desc (exit $actual)"
        PASS=$((PASS + 1))
    else
        echo "FAIL: $desc (expected $expected, got $actual)"
        FAIL=$((FAIL + 1))
    fi
}

assert_stderr_contains() {
    local pattern="$1"
    shift
    local desc="$1"
    shift
    set +e
    local output
    output=$("$@" 2>&1 >/dev/null)
    local actual="$?"
    set -e
    if echo "$output" | grep -F -q -- "$pattern"; then
        echo "PASS: $desc (matched '$pattern')"
        PASS=$((PASS + 1))
    else
        echo "FAIL: $desc (expected pattern '$pattern', got output: '$output')"
        FAIL=$((FAIL + 1))
    fi
}

echo "=== Running CLI Edge-Case Tests ==="

assert_exit 0 "Help flag --help" "$BIN" --help
assert_exit 0 "Help flag -h" "$BIN" -h
assert_exit 1 "No arguments" "$BIN"
assert_stderr_contains "usage:" "Usage output on no arguments" "$BIN"

assert_exit 1 "Missing --allow-dir" "$BIN" -- echo 1
assert_stderr_contains "missing required option --allow-dir" "Missing --allow-dir message" "$BIN" -- echo 1

assert_exit 1 "Missing argument to --allow-dir" "$BIN" --allow-dir
assert_stderr_contains "--allow-dir requires a path argument" "Missing arg message" "$BIN" --allow-dir

assert_exit 1 "Empty string for --allow-dir" "$BIN" --allow-dir "" -- echo 1
assert_stderr_contains "--allow-dir path must not be empty" "Empty allow-dir message" "$BIN" --allow-dir "" -- echo 1


assert_exit 1 "Missing command after --" "$BIN" --allow-dir /tmp --
assert_stderr_contains "missing command after '--'" "Missing command message" "$BIN" --allow-dir /tmp --

assert_exit 1 "Empty command string after --" "$BIN" --allow-dir /tmp -- ""
assert_stderr_contains "missing command after '--'" "Empty command message" "$BIN" --allow-dir /tmp -- ""

assert_exit 1 "Unrecognized option" "$BIN" --foo --allow-dir /tmp -- echo 1
assert_stderr_contains "unrecognized option '--foo'" "Unrecognized option message" "$BIN" --foo --allow-dir /tmp -- echo 1

echo "CLI Tests Completed: $PASS passed, $FAIL failed."
if [ "$FAIL" -ne 0 ]; then
    exit 1
fi

assert_exit 1 "Missing arg to --env" "$BIN" --allow-dir /tmp --env -- echo 1
assert_stderr_contains "--env requires a KEY=VAL argument" "Missing env arg message" "$BIN" --allow-dir /tmp --env -- echo 1

assert_exit 1 "Invalid format for --env" "$BIN" --allow-dir /tmp --env INVALID -- echo 1
assert_stderr_contains "--env requires format KEY=VAL" "Invalid env format message" "$BIN" --allow-dir /tmp --env INVALID -- echo 1

assert_exit 1 "Missing arg to --keep-env" "$BIN" --allow-dir /tmp --keep-env -- echo 1
assert_stderr_contains "--keep-env requires a KEY argument" "Missing keep-env arg message" "$BIN" --allow-dir /tmp --keep-env -- echo 1

assert_exit 1 "Invalid keep-env name containing =" "$BIN" --allow-dir /tmp --keep-env FOO=BAR -- echo 1
assert_stderr_contains "--keep-env requires a valid variable name" "Invalid keep-env message" "$BIN" --allow-dir /tmp --keep-env FOO=BAR -- echo 1

assert_exit 1 "Missing arg to --timeout" "$BIN" --allow-dir /tmp --timeout -- echo 1
assert_stderr_contains "--timeout requires a seconds argument" "Missing timeout arg message" "$BIN" --allow-dir /tmp --timeout -- echo 1

assert_exit 1 "Invalid zero --timeout" "$BIN" --allow-dir /tmp --timeout 0 -- echo 1
assert_stderr_contains "--timeout must be a positive integer" "Invalid zero timeout message" "$BIN" --allow-dir /tmp --timeout 0 -- echo 1

assert_exit 1 "Invalid negative --timeout" "$BIN" --allow-dir /tmp --timeout -5 -- echo 1
assert_stderr_contains "--timeout must be a positive integer" "Invalid negative timeout message" "$BIN" --allow-dir /tmp --timeout -5 -- echo 1

assert_exit 1 "Invalid non-numeric --timeout" "$BIN" --allow-dir /tmp --timeout abc -- echo 1
assert_stderr_contains "--timeout must be a positive integer" "Invalid non-numeric timeout message" "$BIN" --allow-dir /tmp --timeout abc -- echo 1

assert_exit 1 "Missing arg to --ro-dir" "$BIN" --allow-dir /tmp --ro-dir -- echo 1
assert_stderr_contains "--ro-dir requires a path argument" "Missing ro-dir arg message" "$BIN" --allow-dir /tmp --ro-dir -- echo 1

assert_exit 1 "Empty string for --ro-dir" "$BIN" --allow-dir /tmp --ro-dir "" -- echo 1
assert_stderr_contains "--ro-dir path must not be empty" "Empty ro-dir message" "$BIN" --allow-dir /tmp --ro-dir "" -- echo 1

assert_exit 1 "Missing arg to --max-mem" "$BIN" --allow-dir /tmp --max-mem -- echo 1
assert_stderr_contains "--max-mem requires a positive integer" "Missing max-mem arg message" "$BIN" --allow-dir /tmp --max-mem -- echo 1

assert_exit 1 "Invalid non-numeric --max-mem" "$BIN" --allow-dir /tmp --max-mem foo -- echo 1
assert_stderr_contains "--max-mem requires a positive integer" "Invalid max-mem message" "$BIN" --allow-dir /tmp --max-mem foo -- echo 1

assert_exit 1 "Missing arg to --max-cpu" "$BIN" --allow-dir /tmp --max-cpu -- echo 1
assert_stderr_contains "--max-cpu requires a positive integer" "Missing max-cpu arg message" "$BIN" --allow-dir /tmp --max-cpu -- echo 1

assert_exit 1 "Missing arg to --max-procs" "$BIN" --allow-dir /tmp --max-procs -- echo 1
assert_stderr_contains "--max-procs requires a positive integer" "Missing max-procs arg message" "$BIN" --allow-dir /tmp --max-procs -- echo 1

assert_exit 1 "Missing arg to --max-files" "$BIN" --allow-dir /tmp --max-files -- echo 1
assert_stderr_contains "--max-files requires a positive integer" "Missing max-files arg message" "$BIN" --allow-dir /tmp --max-files -- echo 1

assert_exit 1 "Missing arg to --allow-net-connect" "$BIN" --allow-dir /tmp --allow-net-connect -- echo 1
assert_stderr_contains "--allow-net-connect requires a valid port" "Missing connect port message" "$BIN" --allow-dir /tmp --allow-net-connect -- echo 1

assert_exit 1 "Invalid non-numeric --allow-net-connect" "$BIN" --allow-dir /tmp --allow-net-connect foo -- echo 1
assert_stderr_contains "--allow-net-connect requires a valid port" "Invalid connect port non-numeric" "$BIN" --allow-dir /tmp --allow-net-connect foo -- echo 1

assert_exit 1 "Invalid out of range --allow-net-connect" "$BIN" --allow-dir /tmp --allow-net-connect 70000 -- echo 1
assert_stderr_contains "--allow-net-connect requires a valid port" "Invalid connect port range" "$BIN" --allow-dir /tmp --allow-net-connect 70000 -- echo 1

assert_exit 1 "Missing arg to --allow-net-bind" "$BIN" --allow-dir /tmp --allow-net-bind -- echo 1
assert_stderr_contains "--allow-net-bind requires a valid port" "Missing bind port message" "$BIN" --allow-dir /tmp --allow-net-bind -- echo 1

assert_exit 1 "Invalid zero port --allow-net-bind" "$BIN" --allow-dir /tmp --allow-net-bind 0 -- echo 1
assert_stderr_contains "--allow-net-bind requires a valid port" "Invalid bind port zero" "$BIN" --allow-dir /tmp --allow-net-bind 0 -- echo 1
