noinst_PROGRAMS = test_all


AM_CXXFLAGS = $(GENERIC_CXXFLAGS) \
              $(ASAN_CFLAGS) \
              $(GTEST_CFLAGS) \
              -I$(top_srcdir)/librawthread/include \
              -I$(top_srcdir)/librawio/include \
              -I$(top_srcdir)/librawstd/include \
              -I$(top_srcdir)/include

AM_LDFLAGS = $(ASAN_LDFLAGS) -pthread \
             $(GTEST_LIBS)


test_all_SOURCES = main.cpp \
                   run.hpp \
                   test_condition.cpp \
                   test_lock.cpp \
                   test_wake.cpp
test_all_LDADD = $(top_builddir)/librawthread/src/librawthread.la \
                 $(top_builddir)/librawio/src/librawio.la \
                 $(top_builddir)/librawstd/src/librawstd.la


test: all
	./test_all


.PHONY: test
