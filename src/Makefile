##
# Flags
#
USE_BACKEND=mem
USE_IOENGINE=liburing


##
# Setup
#
CC=gcc
CFLAGS=-std=gnu99 -Wall -Wextra -Werror -I../include


##
# Soruces
#
DEPS = aio.h \
       backend_mem.h \
       ../include/rawstor.h

OBJS = rawstor.o

ifeq ($(USE_BACKEND),mem)
    OBJS += rawstor_mem.o
else
    $(error Unexpected BACKEND: $(USE_BACKEND))
endif

ifeq ($(USE_IOENGINE),liburing)
    CFLAGS += $(shell pkg-config --cflags liburing)
    OBJS += aio_liburing.o
else
    $(error Unexpected IOENGINE: $(USE_IOENGINE))
endif


##
# Targets
#
%.o: %.c
	$(CC) $(CFLAGS) $< -c -o $@

%.a: $(OBJS)
	ar rcs $@ $^

all: librawstor.a

clean:
	rm -f *.o librawstor.a

.PHONY: all clean
