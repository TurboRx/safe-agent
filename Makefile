CC ?= gcc
CFLAGS ?= -Wall -Wextra -pedantic -std=c11 -O2
CPPFLAGS ?= -D_GNU_SOURCE -Iinclude

TARGET = safe-agent
SRCS = src/main.c src/sandbox.c src/seccomp_filter.c
OBJS = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

src/%.o: src/%.c include/sandbox.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

clean:
	rm -f src/*.o $(TARGET)

.PHONY: all clean
