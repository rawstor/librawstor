noinst_PROGRAMS = test_threading \
                  test_uuid


AM_CFLAGS = -std=gnu99 -Wall -Wextra -Werror \
            -I$(top_srcdir)/include \
            -I$(top_srcdir)/src


test_threading_SOURCES = test_threading.c
test_threading_LDADD = $(top_srcdir)/src/librawstor.la


test_uuid_SOURCES = test_uuid.c
test_uuid_LDADD = $(top_srcdir)/src/librawstor.la


test: all
	@for test in $(noinst_PROGRAMS); do \
	    echo $${test}; \
	    ./$${test} || exit 1; \
	done
	@echo Success!!!


.PHONY: test
