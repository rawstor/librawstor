##
# Flags
#
USE_IOENGINE=liburing


##
# Setup
#
CC=gcc
CFLAGS=-std=gnu99 -Wall -Wextra -Werror -I../include
LIBS=-L../src -lrawstor


##
# Soruces
#
DEPS = protocol.h \
       server.h \
       ../include/rawstor.h

OBJS = main.o \
       server.o

ifeq ($(USE_IOENGINE),liburing)
    LIBS += $(shell pkg-config --libs liburing)
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
