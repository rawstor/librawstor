##
# Flags
#
USE_IOENGINE=liburing


##
# Setup
#
define assert
	$(if $1,,$(error Assertion failed: $2))
endef


CC=gcc
CFLAGS=-std=gnu99 -Wall -Wextra -Werror -I../include
LIBS=-L../src -lrawstor


##
# Soruces
#
DEPS = server.h \
       ../include/rawstor.h

OBJS = main.o


ifeq ($(USE_IOENGINE),liburing)
    LIBS += $(shell pkg-config --libs liburing)
    CFLAGS += $(shell pkg-config --cflags liburing)
	OBJS += server.o
else ifeq ($(USE_IOENGINE),libevent)
    LIBS += $(shell pkg-config --libs libevent)
    CFLAGS += $(shell pkg-config --cflags libevent)
else
    $(error Unexpected IOENGINE: $(USE_IOENGINE))
endif


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
