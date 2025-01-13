CC=gcc
CFLAGS=-std=gnu99 -Wall -Wextra -Werror -I../src
LIBS=-L../src -lrawstor

DEPS = server.h

OBJS = main.o \
       server.o


%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) $< -c -o $@

rawstor-vhost-user-server: $(OBJS)
	$(CC) -o $@ $^ $(LIBS)

all: rawstor-vhost-user-server

clean:
	rm -f *.o rawstor-vhost-user-server

.PHONY: all clean
