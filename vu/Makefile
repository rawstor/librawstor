URING_CFLAGS=$(shell pkg-config --cflags liburing)
URING_LIBS=$(shell pkg-config --libs liburing)

CC=gcc
CFLAGS=-std=gnu99 -Wall -Wextra -Werror -I../include $(URING_CFLAGS)
LIBS=-L../src -lrawstor $(URING_LIBS)

DEPS = server.h \
       ../include/rawstor.h

OBJS = main.o \
       server.o


%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) $< -c -o $@

rawstor-vu: $(OBJS)
	$(CC) -o $@ $^ $(LIBS)

all: rawstor-vu

clean:
	rm -f *.o rawstor-vu

.PHONY: all clean
