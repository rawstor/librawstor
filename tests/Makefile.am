noinst_PROGRAMS = test_pool


AM_CFLAGS = -std=gnu99 -Wall -Wextra -Werror \
            -I$(top_srcdir)/include \
            -I$(top_srcdir)/src


test_pool_SOURCES = test_pool.c


test_pool_LDADD = $(top_srcdir)/src/librawstor.la


test: all
	@for test in $(TESTS); do \
	    echo $${test}; \
	    ./$${test} || exit 1; \
	done
	@echo Success!!!


.PHONY: test
