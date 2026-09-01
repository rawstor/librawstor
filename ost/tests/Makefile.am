noinst_PROGRAMS = test_all


AM_CXXFLAGS = $(GENERIC_CXXFLAGS) \
              $(ASAN_CFLAGS) \
              $(GTEST_CFLAGS) \
              -I$(top_srcdir)/librawstd/include \
              -I$(top_srcdir)/include \
              -I$(top_srcdir)/ost/include

AM_LDFLAGS = $(ASAN_LDFLAGS) \
             $(GTEST_LIBS)


test_all_SOURCES = client.cpp \
                   client.hpp \
                   main.cpp \
                   queue.cpp \
                   queue.hpp \
                   test_client.cpp \
                   tmp_dir.cpp \
                   tmp_dir.hpp
test_all_LDADD = $(top_builddir)/ost/src/libost.la \
                 $(top_builddir)/src/librawstor.la \
                 $(top_builddir)/librawstd/src/librawstd.la


test: all
	./test_all


.PHONY: test
