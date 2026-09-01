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
                   test_object.cpp \
                   test_pagination_token.cpp
test_all_LDADD = $(top_builddir)/src/librawstor.la


test: all
	./test_all


.PHONY: test
