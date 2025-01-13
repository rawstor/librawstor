##
# Flags
#
USE_BACKEND=mem


CC=gcc
CFLAGS=-std=gnu99 -Wall -Wextra -Werror -I../include

DEPS = backend_mem.h \
       ../include/rawstor.h

OBJS = rawstor.o

ifeq ($(USE_BACKEND),mem)
    OBJS += rawstor_mem.o
else
    $(error Unexpected BACKEND: $(USE_BACKEND))
endif

%.o: %.c
	$(CC) $(CFLAGS) $< -c -o $@

%.a: $(OBJS)
	ar rcs $@ $^

all: librawstor.a

clean:
	rm -f *.o librawstor.a

.PHONY: all clean
