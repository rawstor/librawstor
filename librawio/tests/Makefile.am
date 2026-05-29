noinst_PROGRAMS = test_all


AM_CXXFLAGS = $(GENERIC_CXXFLAGS) \
              $(ASAN_CFLAGS) \
              $(GTEST_CFLAGS) \
              -I$(top_srcdir)/librawstd/include \
              -I$(top_srcdir)/librawio/src \
              -I$(top_srcdir)/librawio/include \
              -I$(top_srcdir)/include

AM_LDFLAGS = $(ASAN_LDFLAGS) \
             $(GTEST_LIBS)


test_all_SOURCES = main.cpp \
                   fixture.hpp \
                   fixture.cpp \
                   server.hpp \
                   server.cpp \
                   socket.hpp \
                   socket.cpp \
                   test_basics.cpp \
                   test_cancel.cpp \
                   test_multiplex.cpp \
                   test_multishot.cpp \
                   test_overflow.cpp \
                   test_pollhup.cpp
test_all_LDADD = $(top_builddir)/librawio/src/librawio.la \
                 $(top_builddir)/librawstd/src/librawstd.la


test: all
	./test_all


.PHONY: test
