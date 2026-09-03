noinst_LTLIBRARIES = libost.la

bin_PROGRAMS = rawstor-ost

AM_CXXFLAGS = $(GENERIC_CXXFLAGS) \
              $(ASAN_CFLAGS) \
              -pthread \
              -I$(top_srcdir)/ost/include \
              -I$(top_srcdir)/librawstd/include \
              -I$(top_srcdir)/include \
              -I$(top_srcdir)/src

AM_LDFLAGS = $(ASAN_LDFLAGS) \
             -pthread


libost_la_SOURCES = $(top_srcdir)/ost/include/ost/server.hpp \
                    $(top_srcdir)/ost/include/ost/client.hpp \
                    server.cpp \
                    client.cpp

rawstor_ost_SOURCES = main.cpp

rawstor_ost_LDADD = libost.la \
                    $(top_builddir)/src/librawstor.la \
                    $(top_builddir)/librawstd/src/librawstd.la \
                    -lstdc++
