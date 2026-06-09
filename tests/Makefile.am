noinst_PROGRAMS = test_all


AM_CXXFLAGS = $(GENERIC_CXXFLAGS) \
              $(ASAN_CFLAGS) \
              $(GTEST_CFLAGS) \
              -I$(top_srcdir)/librawstd/include \
              -I$(top_srcdir)/librawio/include \
              -I$(top_srcdir)/include \
              -I$(top_srcdir)/src

AM_LDFLAGS = $(ASAN_LDFLAGS) \
             $(GTEST_LIBS)


test_all_SOURCES = backend.hpp \
                   backend.cpp \
                   main.cpp \
                   server.cpp \
                   server.hpp \
                   test_lifecycle.cpp
test_all_LDADD = $(top_builddir)/librawio/src/librawio.la \
                 $(top_builddir)/librawstd/src/librawstd.la \
                 $(top_builddir)/src/librawstor.la


test: all
	./test_all


.PHONY: test
