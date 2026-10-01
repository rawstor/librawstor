noinst_PROGRAMS = test_all


AM_CXXFLAGS = $(GENERIC_CXXFLAGS) \
              $(SQLITE3_CFLAGS) \
              $(ASAN_CFLAGS) \
              $(GTEST_CFLAGS) \
              -I$(top_srcdir)/mds/include \
              -I$(top_srcdir)/librawstd/include \
              -I$(top_srcdir)/include \
              -I$(top_srcdir)/librawio/include

AM_LDFLAGS = $(ASAN_LDFLAGS) \
             $(GTEST_LIBS)


test_all_SOURCES = main.cpp \
                   test_monitor.cpp \
                   test_opts.cpp \
                   test_placement.cpp \
                   test_store.cpp \
                   test_topology.cpp \
                   tmp_dir.cpp \
                   tmp_dir.hpp
test_all_LDADD = $(top_builddir)/mds/src/libmds.la \
                 $(top_builddir)/mds/src/libmdsstore.la \
                 $(top_builddir)/src/librawstor.la \
                 $(top_builddir)/librawstd/src/librawstd.la \
                 $(SQLITE3_LIBS)


test: all
	./test_all


.PHONY: test
