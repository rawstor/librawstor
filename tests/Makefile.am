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


test_all_SOURCES = main.cpp \
                   server.cpp \
                   server.hpp \
                   session.cpp \
                   session.hpp \
                   test_async_api.cpp \
                   test_blkdev.cpp \
                   test_io.cpp \
                   test_lifecycle.cpp \
                   test_mirror.cpp \
                   test_placement.cpp \
                   test_volume.cpp \
                   test_worker.cpp
test_all_LDADD = $(top_builddir)/src/librawstor.la

if WITH_MDS
AM_CXXFLAGS += $(SQLITE3_CFLAGS) -I$(top_srcdir)/mds
test_all_SOURCES += test_mds_store.cpp
test_all_LDADD += $(top_builddir)/mds/libmdsstore.la $(SQLITE3_LIBS)
endif


test: all
	./test_all


.PHONY: test
