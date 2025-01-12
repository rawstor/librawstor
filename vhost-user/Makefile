CC=gcc
CFLAGS=-std=gnu99 -Wall -Wextra -Werror

DEPS = server.h

OBJ = main.o \
      server.o


%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

rawstor-vhost-user-server: $(OBJ)
	$(CC) -o $@ $^

all: rawstor-vhost-user-server

clean:
	rm -f *.o rawstor-vhost-user-server

.PHONY: all clean
