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
                   rawio_sync.hpp \
                   server.cpp \
                   server.hpp \
                   session.cpp \
                   session.hpp \
                   tmp_dir.cpp \
                   tmp_dir.hpp \
                   test_blk_backend.cpp \
                   test_io.cpp \
                   test_lifecycle.cpp \
                   test_list.cpp \
                   test_location_info.cpp \
                   test_mirror.cpp \
                   test_object.cpp \
                   test_pagination_token.cpp
test_all_LDADD = $(top_builddir)/src/librawstor.la

# Volume::snapshot()/snap_remove()'s real MDS+OST wire path needs a live
# rawstor::mds::Server + rawstor::ostserver::Server pair (volume_env.*) --
# the OST side is always built, but mds/ (and its rawstor::mds::Server)
# only exists with sqlite3 (--without-sqlite3).
if WITH_SQLITE3
AM_CXXFLAGS += -pthread \
               -I$(top_srcdir)/ost/include \
               -I$(top_srcdir)/mds/include \
               $(SQLITE3_CFLAGS)
AM_LDFLAGS += -pthread
test_all_SOURCES += volume_env.cpp \
                    volume_env.hpp \
                    test_volume.cpp
test_all_LDADD += $(top_builddir)/ost/src/libost.la \
                  $(top_builddir)/mds/libmds.la \
                  $(top_builddir)/mds/libmdsstore.la \
                  $(SQLITE3_LIBS) \
                  -lstdc++
endif


test: all
	./test_all


.PHONY: test
