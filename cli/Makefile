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
DEPS = ../include/rawstor.h

OBJS = create.o\
       main.o


##
# Targets
#
%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) $< -c -o $@

rawstor-cli: $(OBJS)
	$(CC) -o $@ $^ $(LIBS)

all: rawstor-cli

clean:
	rm -f *.o rawstor-cli

.PHONY: all clean
