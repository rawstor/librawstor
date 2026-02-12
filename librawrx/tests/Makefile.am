noinst_PROGRAMS = test_all


AM_CXXFLAGS = $(GENERIC_CXXFLAGS) \
              $(ASAN_CFLAGS) \
              $(GTEST_CFLAGS) \
              -I$(top_srcdir)/librawrx/include

AM_LDFLAGS = $(ASAN_LDFLAGS) \
             $(GTEST_LIBS)


test_all_SOURCES = test_observable.cpp \
                   test_pipe.cpp \
                   test_usecase.cpp
test_all_LDADD = $(top_builddir)/librawrx/src/librawrx.la -lgtest_main


test: all
	./test_all


.PHONY: test
