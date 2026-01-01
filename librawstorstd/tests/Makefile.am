noinst_PROGRAMS = test_all \
                  test_list \
                  test_mempool \
                  test_threading \
                  test_uri \
                  test_uuid


AM_CFLAGS = $(GENERIC_CFLAGS) \
            $(ASAN_CFLAGS) \
            $(GTEST_CFLAGS) \
            -I$(top_srcdir)/librawstorstd/src \
            -I$(top_srcdir)/librawstorstd/include \
            -I$(top_srcdir)/tests \
            -I$(top_srcdir)/include

AM_CXXFLAGS = $(GENERIC_CXXFLAGS) \
              $(ASAN_CFLAGS) \
              $(GTEST_CFLAGS) \
              -I$(top_srcdir)/librawstorstd/src \
              -I$(top_srcdir)/librawstorstd/include \
              -I$(top_srcdir)/tests \
              -I$(top_srcdir)/include

AM_LDFLAGS = $(ASAN_LDFLAGS) \
             $(GTEST_LIBS) -lgtest_main


test_all_SOURCES = test_hash.cpp \
                   test_iovec.cpp \
                   test_ringbuf.cpp
test_all_LDADD = $(top_builddir)/librawstorstd/src/librawstorstd.la


test_list_SOURCES = test_list.c
test_list_LDADD = $(top_builddir)/librawstorstd/src/librawstorstd.la


test_mempool_SOURCES = test_mempool.c
test_mempool_LDADD = $(top_builddir)/librawstorstd/src/librawstorstd.la


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
