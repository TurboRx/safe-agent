CC ?= gcc
CFLAGS ?= -Wall -Wextra -pedantic -std=c11 -O2
CPPFLAGS ?= -D_GNU_SOURCE -Iinclude

TARGET = safe-agent
SRCS = src/main.c src/sandbox.c src/seccomp_filter.c
OBJS = $(SRCS:.c=.o)

TEST_BINS = tests/test_seccomp tests/test_landlock_mock

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

src/%.o: src/%.c include/sandbox.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

tests/test_seccomp: src/seccomp_filter.c tests/test_seccomp.c include/sandbox.h
	$(CC) $(CFLAGS) $(CPPFLAGS) src/seccomp_filter.c tests/test_seccomp.c -o $@

tests/test_landlock_mock: src/sandbox.c tests/test_landlock_mock.c include/sandbox.h
	$(CC) $(CFLAGS) $(CPPFLAGS) src/sandbox.c tests/test_landlock_mock.c -o $@

test: $(TARGET) $(TEST_BINS)
	./tests/test_cli.sh
	./tests/test_seccomp
	./tests/test_landlock_mock

clean:
	rm -f src/*.o $(TARGET) $(TEST_BINS)

.PHONY: all test clean
