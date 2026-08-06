noinst_PROGRAMS = test_all


AM_CXXFLAGS = $(GENERIC_CXXFLAGS) \
              $(ASAN_CFLAGS) \
              $(GTEST_CFLAGS) \
              -I$(top_srcdir)/librawstd/include \
              -I$(top_srcdir)/include \
              -I$(top_srcdir)/vduse/include

AM_LDFLAGS = $(ASAN_LDFLAGS) \
             $(GTEST_LIBS)


test_all_SOURCES = main.cpp \
                   test_request.cpp
test_all_LDADD = $(top_builddir)/vduse/src/libvduse.la \
                 $(top_builddir)/src/librawstor.la \
                 $(top_builddir)/librawstd/src/librawstd.la


test: all
	./test_all


.PHONY: test
