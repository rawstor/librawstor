noinst_PROGRAMS = test_all


AM_CXXFLAGS = $(GENERIC_CXXFLAGS) \
              $(ASAN_CFLAGS) \
              $(GTEST_CFLAGS) \
              -I$(top_srcdir)/librawstorstd/include \
              -I$(top_srcdir)/librawstorio/include \
              -I$(top_srcdir)/include \
              -I$(top_srcdir)/src

AM_LDFLAGS = $(ASAN_LDFLAGS) \
             $(GTEST_LIBS)


test_all_SOURCES = main.cpp \
                   fixture.hpp \
                   server.cpp \
                   server.hpp \
                   test_lifecycle.cpp
test_all_LDADD = $(top_builddir)/librawstorio/src/librawstorio.la \
                 $(top_builddir)/librawstorstd/src/librawstorstd.la \
                 $(top_builddir)/src/librawstor.la


test: all
	./test_all


.PHONY: test
