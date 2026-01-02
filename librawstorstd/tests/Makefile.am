noinst_PROGRAMS = test_all


AM_CXXFLAGS = $(GENERIC_CXXFLAGS) \
              $(ASAN_CFLAGS) \
              $(GTEST_CFLAGS) \
              -I$(top_srcdir)/librawstorstd/src \
              -I$(top_srcdir)/librawstorstd/include \
              -I$(top_srcdir)/include

AM_LDFLAGS = $(ASAN_LDFLAGS) \
             $(GTEST_LIBS)


test_all_SOURCES = test_hash.cpp \
                   test_iovec.cpp \
                   test_list.cpp \
                   test_mempool.cpp \
                   test_ringbuf.cpp \
                   test_threading.cpp \
                   test_uri.cpp \
                   test_uuid.cpp
test_all_LDADD = $(top_builddir)/librawstorstd/src/librawstorstd.la -lgtest_main


test: all
	./test_all


.PHONY: test
