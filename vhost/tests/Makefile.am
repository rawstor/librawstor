noinst_PROGRAMS = test_all


AM_CXXFLAGS = $(GENERIC_CXXFLAGS) \
              $(ASAN_CFLAGS) \
              $(GTEST_CFLAGS) \
              -I$(top_srcdir)/librawstd/include \
              -I$(top_srcdir)/include \
              -I$(top_srcdir)/vhost

AM_LDFLAGS = $(ASAN_LDFLAGS) \
             $(GTEST_LIBS)


test_all_SOURCES = main.cpp \
                   test_virtqueue.cpp \
                   $(top_srcdir)/vhost/device.cpp \
                   $(top_srcdir)/vhost/device.hpp \
                   $(top_srcdir)/vhost/devregion.cpp \
                   $(top_srcdir)/vhost/devregion.hpp \
                   $(top_srcdir)/vhost/protocol.h \
                   $(top_srcdir)/vhost/ring.cpp \
                   $(top_srcdir)/vhost/ring.hpp \
                   $(top_srcdir)/vhost/virtqueue.cpp \
                   $(top_srcdir)/vhost/virtqueue.hpp
test_all_LDADD = $(top_builddir)/src/librawstor.la \
                 $(top_builddir)/librawstd/src/librawstd.la


test: all
	./test_all


.PHONY: test
