noinst_LTLIBRARIES = librawrx.la


AM_CXXFLAGS = $(GENERIC_CXXFLAGS) \
              $(ASAN_CFLAGS) \
              -I$(top_srcdir)/librawrx/include

AM_LDFLAGS = $(ASAN_LDFLAGS)


librawrx_la_SOURCES = $(top_srcdir)/librawrx/include/rawrx/observable.hpp \
                      observable.cpp

librawrx_la_LIBADD =
