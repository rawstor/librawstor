##
# Flags
#
USE_BACKEND = file
USE_IOENGINE = liburing


##
# Setup
#
CC = gcc
CFLAGS = -std=gnu99 -Wall -Wextra -Werror -I../include


##
# Sources
#
DEPS = aio.h \
       backend_mem.h \
       pool.h \
       ../include/rawstor.h

OBJS = pool.o \
       rawstor.o

REQUIRES =

ifeq ($(USE_BACKEND),file)
    OBJS += object_file.o
else
    $(error Unexpected BACKEND: $(USE_BACKEND))
endif

ifeq ($(USE_IOENGINE),liburing)
    CFLAGS += $(shell pkg-config --cflags liburing)
    OBJS += aio_liburing.o
    REQUIRES += liburing
else
    $(error Unexpected IOENGINE: $(USE_IOENGINE))
endif


##
# Targets
#
%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) $< -c -o $@

%.a: $(OBJS)
	ar rcs $@ $^

all: librawstor.a rawstor.pc

clean:
	rm -f *.o librawstor.a rawstor.pc


##
# Templates
#
rawstor.pc: rawstor.pc.tpl Makefile
	export LIBDIR=$(CURDIR); \
	export INCLUDEDIR=$(CURDIR)/../include; \
	export REQUIRES=$(REQUIRES); \
	cat $< | envsubst > $@


.PHONY: all clean
