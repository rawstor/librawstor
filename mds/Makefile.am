bin_PROGRAMS = rawstor-mds

noinst_LTLIBRARIES = libmdsstore.la


AM_CXXFLAGS = $(GENERIC_CXXFLAGS) \
              $(SQLITE3_CFLAGS) \
              $(ASAN_CFLAGS) \
              -I$(top_srcdir)/librawstd/include \
              -I$(top_srcdir)/librawio/include \
              -I$(top_srcdir)/include \
              -I$(top_srcdir)/src

AM_LDFLAGS = $(ASAN_LDFLAGS)


libmdsstore_la_SOURCES = store.cpp \
                         store.hpp

rawstor_mds_SOURCES = main.cpp \
                      server.cpp \
                      server.hpp \
                      session.cpp \
                      session.hpp

rawstor_mds_LDADD = libmdsstore.la \
                    $(top_builddir)/src/librawstor.la \
                    $(SQLITE3_LIBS)
