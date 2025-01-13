##
# Flags
#
ENABLE_LIBEVENT=yes
ENABLE_LIBURING=no


##
# Setup
#
define assert
	$(if $1,,$(error Assertion failed: $2))
endef


CC=gcc
CFLAGS=-std=gnu99 -Wall -Wextra -Werror -I../include
LIBS=-L../src -lrawstor

ifeq ($(ENABLE_LIBEVENT),yes)
	LIBS += $(shell pkg-config --libs libevent)
	CFLAGS += -DENABLE_LIBEVENT=1 $(shell pkg-config --cflags libevent)
	IO_ENGINE_DEFINED = 1
endif

ifeq ($(ENABLE_LIBURING),yes)
	LIBS += $(shell pkg-config --libs liburing)
	CFLAGS += -DENABLE_LIBURING=1 $(shell pkg-config --cflags liburing)
	IO_ENGINE_DEFINED = 1
endif

$(call assert,$(IO_ENGINE_DEFINED),No io engine defined)


##
# Soruces
#
DEPS = server.h \
       ../include/rawstor.h

OBJS = main.o \
       server.o


##
# Targets
#
%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) $< -c -o $@

rawstor-vu: $(OBJS)
	$(CC) -o $@ $^ $(LIBS)

all: rawstor-vu

clean:
	rm -f *.o rawstor-vu

.PHONY: all clean
