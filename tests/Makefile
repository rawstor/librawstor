##
# Setup
#
CC = gcc
CFLAGS = -std=gnu99 -Wall -Wextra -Werror -I../include -I../src

CFLAGS += $(shell PKG_CONFIG_PATH=$(CURDIR)/../src pkg-config --cflags rawstor)
LIBS += $(shell PKG_CONFIG_PATH=$(CURDIR)/../src pkg-config --libs rawstor)


##
# Sources
#
DEPS = utils.h


##
# Tests
#
TESTS = test_pool

##
# Targets
#
%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) $< -c -o $@


all: $(TESTS)


test_pool: test_pool.o
	$(CC) -o $@ $^ $(LIBS)


test: all
	@for test in $(TESTS); do \
	    echo $${test}; \
	    ./$${test} || exit 1; \
	done
	@echo Success!!!


clean:
	rm -f *.o $(TESTS)


.PHONY: all clean test
