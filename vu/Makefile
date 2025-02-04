##
# Flags
#


##
# Setup
#
CC = gcc
CFLAGS = -std=gnu99 -Wall -Wextra -Werror -I../include
LIBS = 

CFLAGS += $(shell PKG_CONFIG_PATH=$(CURDIR)/../src pkg-config --cflags rawstor)
LIBS += $(shell PKG_CONFIG_PATH=$(CURDIR)/../src pkg-config --libs rawstor)


##
# Sources
#
DEPS = gcc.h \
       protocol.h \
       server.h \
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
