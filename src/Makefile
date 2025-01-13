CC=gcc
CFLAGS=-std=gnu99 -Wall -Wextra -Werror -I../include

DEPS = backend.h \
       backend_mem.h \
       rawstor.h

OBJS = backend_mem.o \
       rawstor.o


%.o: %.c
	$(CC) $(CFLAGS) $< -c -o $@

%.a: $(OBJS)
	ar rcs $@ $^

all: librawstor.a

clean:
	rm -f *.o librawstor.a

.PHONY: all clean
