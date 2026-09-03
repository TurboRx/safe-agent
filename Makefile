CC ?= gcc
CFLAGS ?= -Wall -Wextra -pedantic -std=c11 -O2
CPPFLAGS ?= -D_GNU_SOURCE -Iinclude

TARGET = safe-agent
SRCS = src/main.c src/sandbox.c src/seccomp_filter.c src/env.c src/supervisor.c src/rlimit.c src/netns.c src/pidns.c
OBJS = $(SRCS:.c=.o)

TEST_BINS = tests/test_seccomp tests/test_landlock_mock tests/test_env tests/test_supervisor tests/test_rlimit tests/test_netns tests/test_pidns

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

src/%.o: src/%.c include/sandbox.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

tests/test_seccomp: src/seccomp_filter.c tests/test_seccomp.c include/sandbox.h
	$(CC) $(CFLAGS) $(CPPFLAGS) src/seccomp_filter.c tests/test_seccomp.c -o $@

tests/test_landlock_mock: src/sandbox.c tests/test_landlock_mock.c include/sandbox.h
	$(CC) $(CFLAGS) $(CPPFLAGS) src/sandbox.c tests/test_landlock_mock.c -o $@

tests/test_env: src/env.c tests/test_env.c include/sandbox.h
	$(CC) $(CFLAGS) $(CPPFLAGS) src/env.c tests/test_env.c -o $@

tests/test_supervisor: src/supervisor.c src/env.c src/rlimit.c src/netns.c src/pidns.c tests/test_supervisor.c include/sandbox.h
	$(CC) $(CFLAGS) $(CPPFLAGS) src/supervisor.c src/env.c src/rlimit.c src/netns.c src/pidns.c tests/test_supervisor.c -o $@

tests/test_rlimit: src/rlimit.c tests/test_rlimit.c include/sandbox.h
	$(CC) $(CFLAGS) $(CPPFLAGS) src/rlimit.c tests/test_rlimit.c -o $@

tests/test_netns: src/netns.c tests/test_netns.c include/sandbox.h
	$(CC) $(CFLAGS) $(CPPFLAGS) src/netns.c tests/test_netns.c -o $@

tests/test_pidns: src/pidns.c tests/test_pidns.c include/sandbox.h
	$(CC) $(CFLAGS) $(CPPFLAGS) src/pidns.c tests/test_pidns.c -o $@

test: $(TARGET) $(TEST_BINS)
	./tests/test_cli.sh
	./tests/test_seccomp
	./tests/test_landlock_mock
	./tests/test_env
	./tests/test_supervisor
	./tests/test_rlimit
	./tests/test_netns
	./tests/test_pidns

clean:
	rm -f src/*.o $(TARGET) $(TEST_BINS)

.PHONY: all test clean
