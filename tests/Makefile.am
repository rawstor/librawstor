noinst_PROGRAMS = test_iovec_routines \
                  test_mempool \
                  test_ringbuf \
                  test_threading \
                  test_uuid


AM_CFLAGS = -std=gnu99 -Wall -Wextra -Werror \
            -I$(top_srcdir)/include \
            -I$(top_srcdir)/src


test_iovec_routines_SOURCES = test_iovec_routines.c
test_iovec_routines_LDADD = $(top_srcdir)/src/librawstor.la


test_mempool_SOURCES = test_mempool.c
test_mempool_LDADD = $(top_srcdir)/src/librawstor.la


test_ringbuf_SOURCES = test_ringbuf.c
test_ringbuf_LDADD = $(top_srcdir)/src/librawstor.la


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
