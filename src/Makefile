##
# Flags
#
USE_BACKEND = mem
USE_IOENGINE = liburing


##
# Setup
#
CC = gcc
CFLAGS = -std=gnu99 -Wall -Wextra -Werror -I../include


##
# Soruces
#
DEPS = aio.h \
       backend_mem.h \
       stack_buffer.h \
       ../include/rawstor.h

OBJS = rawstor.o \
       stack_buffer.o

REQUIRES =

ifeq ($(USE_BACKEND),mem)
    OBJS += rawstor_mem.o
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
%.o: %.c
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
