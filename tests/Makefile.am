noinst_PROGRAMS = test_mempool \
                  test_uuid


AM_CFLAGS = -std=gnu99 -Wall -Wextra -Werror \
            -I$(top_srcdir)/include \
            -I$(top_srcdir)/src


test_mempool_SOURCES = test_mempool.c


test_mempool_LDADD = $(top_srcdir)/src/librawstor.la


test_uuid_SOURCES = test_uuid.c


test_uuid_LDADD = $(top_srcdir)/src/librawstor.la


test: all
	@for test in $(noinst_PROGRAMS); do \
	    echo $${test}; \
	    ./$${test} || exit 1; \
	done
	@echo Success!!!


.PHONY: test
