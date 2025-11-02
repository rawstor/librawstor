noinst_PROGRAMS = test_hash \
                  test_iovec \
                  test_list \
                  test_mempool \
                  test_ringbuf \
                  test_threading \
                  test_uri \
                  test_uuid


AM_CFLAGS = $(GENERIC_CFLAGS) \
            $(ASAN_CFLAGS) \
            -I$(top_srcdir)/librawstorstd/src \
            -I$(top_srcdir)/librawstorstd/include \
            -I$(top_srcdir)/tests \
            -I$(top_srcdir)/include

AM_CXXFLAGS = $(GENERIC_CXXFLAGS) \
              $(ASAN_CFLAGS) \
              -I$(top_srcdir)/librawstorstd/src \
              -I$(top_srcdir)/librawstorstd/include \
              -I$(top_srcdir)/tests \
              -I$(top_srcdir)/include

AM_LDFLAGS = $(ASAN_LDFLAGS)


test_hash_SOURCES = test_hash.c
test_hash_LDADD = $(top_builddir)/librawstorstd/src/librawstorstd.la


test_iovec_SOURCES = test_iovec.c
test_iovec_LDADD = $(top_builddir)/librawstorstd/src/librawstorstd.la


test_list_SOURCES = test_list.c
test_list_LDADD = $(top_builddir)/librawstorstd/src/librawstorstd.la


test_mempool_SOURCES = test_mempool.c
test_mempool_LDADD = $(top_builddir)/librawstorstd/src/librawstorstd.la


test_ringbuf_SOURCES = test_ringbuf.cpp
test_ringbuf_LDADD = $(top_builddir)/librawstorstd/src/librawstorstd.la


test_threading_SOURCES = test_threading.c
test_threading_LDADD = $(top_builddir)/librawstorstd/src/librawstorstd.la


test_uri_SOURCES = test_uri.cpp
test_uri_LDADD = $(top_builddir)/librawstorstd/src/librawstorstd.la


test_uuid_SOURCES = test_uuid.c
test_uuid_LDADD = $(top_builddir)/librawstorstd/src/librawstorstd.la


test: all
	@for test in $(noinst_PROGRAMS); do \
	    echo $${test}; \
	    ./$${test} || exit 1; \
	done
	@echo Success!!!


.PHONY: test
