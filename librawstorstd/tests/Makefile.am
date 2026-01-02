noinst_PROGRAMS = test_all


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
                   test_list.cpp \
                   test_mempool.cpp \
                   test_ringbuf.cpp \
                   test_threading.cpp \
                   test_uri.cpp \
                   test_uuid.cpp
test_all_LDADD = $(top_builddir)/librawstorstd/src/librawstorstd.la


test: all
	@for test in $(noinst_PROGRAMS); do \
	    echo $${test}; \
	    ./$${test} || exit 1; \
	done
	@echo Success!!!


.PHONY: test
