noinst_PROGRAMS = test_all


AM_CXXFLAGS = $(GENERIC_CXXFLAGS) \
              $(ASAN_CFLAGS) \
              $(GTEST_CFLAGS) \
              $(OPENSSL_CFLAGS) \
              -I$(top_srcdir)/librawtls/include \
              -I$(top_srcdir)/librawio/include \
              -I$(top_srcdir)/librawstd/include \
              -I$(top_srcdir)/include

AM_LDFLAGS = $(ASAN_LDFLAGS) -pthread \
             $(GTEST_LIBS) \
             $(OPENSSL_LIBS)


test_all_SOURCES = main.cpp \
                   pki.hpp \
                   test_session.cpp \
                   test_spiffe.cpp \
                   test_transport.cpp
test_all_LDADD = $(top_builddir)/librawtls/src/librawtls.la \
                 $(top_builddir)/librawio/src/librawio.la \
                 $(top_builddir)/librawstd/src/librawstd.la


test: all
	./test_all


.PHONY: test
