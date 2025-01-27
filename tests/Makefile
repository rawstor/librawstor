##
# Setup
#
CC = gcc
CFLAGS = -std=gnu99 -Wall -Wextra -Werror -I../include -I../src


##
# Tests
#
TESTS = test_dummy


##
# Targets
#
all: $(TESTS)


test: $(TESTS)
	@for test in $(TESTS); do \
	    echo $${test}; \
	    ./$${test} || exit 1; \
	done
	@echo Success!!!


clean:
	rm -f $(TESTS)


.PHONY: all clean test
