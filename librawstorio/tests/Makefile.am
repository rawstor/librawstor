noinst_PROGRAMS = test_all


AM_CXXFLAGS = $(GENERIC_CXXFLAGS) \
              $(ASAN_CFLAGS) \
              $(GTEST_CFLAGS) \
              -I$(top_srcdir)/librawstorstd/include \
              -I$(top_srcdir)/librawstorio/src \
              -I$(top_srcdir)/librawstorio/include \
              -I$(top_srcdir)/include

AM_LDFLAGS = $(ASAN_LDFLAGS) \
             $(GTEST_LIBS)


test_all_SOURCES = main.cpp \
                   fixture.hpp \
                   server.hpp \
                   server.cpp \
                   task.hpp \
                   test_basics.cpp \
                   test_multiplex.cpp
test_all_LDADD = $(top_builddir)/librawstorio/src/librawstorio.la \
                 $(top_builddir)/librawstorstd/src/librawstorstd.la


test: all
	./test_all


.PHONY: test
