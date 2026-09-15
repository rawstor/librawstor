bin_PROGRAMS = rawstor-mds

noinst_LTLIBRARIES = libmdsstore.la libmds.la


AM_CXXFLAGS = $(GENERIC_CXXFLAGS) \
              $(SQLITE3_CFLAGS) \
              $(ASAN_CFLAGS) \
              -I$(top_srcdir)/mds/include \
              -I$(top_srcdir)/librawstd/include \
              -I$(top_srcdir)/librawio/include \
              -I$(top_srcdir)/include \
              -I$(top_srcdir)/src

AM_LDFLAGS = $(ASAN_LDFLAGS)


libmdsstore_la_SOURCES = store.cpp \
                         $(top_srcdir)/mds/include/mds/store.hpp

# Split out from rawstor_mds_SOURCES (matching ost/src/Makefile.am's own
# libost.la split) so tests/ can drive a real mds::Server in-process,
# the same way ost/tests/ already reuses ost::Server -- without this,
# Volume::snapshot()/snap_remove()'s actual MDS wire path would be
# untestable outside of spawning the rawstor-mds binary itself.
libmds_la_SOURCES = server.cpp \
                    $(top_srcdir)/mds/include/mds/server.hpp \
                    session.cpp \
                    $(top_srcdir)/mds/include/mds/session.hpp

rawstor_mds_SOURCES = main.cpp

rawstor_mds_LDADD = libmds.la \
                    libmdsstore.la \
                    $(top_builddir)/src/librawstor.la \
                    $(top_builddir)/librawstd/src/librawstd.la \
                    $(SQLITE3_LIBS)
