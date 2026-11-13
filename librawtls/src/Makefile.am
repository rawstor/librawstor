noinst_LTLIBRARIES = librawtls.la


AM_CXXFLAGS = $(GENERIC_CXXFLAGS) \
              $(ASAN_CFLAGS) \
              $(OPENSSL_CFLAGS) \
              -I$(top_srcdir)/librawtls/include \
              -I$(top_srcdir)/librawio/include \
              -I$(top_srcdir)/librawstd/include \
              -I$(top_srcdir)/include

AM_LDFLAGS = $(ASAN_LDFLAGS)


librawtls_la_SOURCES = $(top_srcdir)/librawtls/include/rawtls/context.hpp \
                       $(top_srcdir)/librawtls/include/rawtls/op.hpp \
                       $(top_srcdir)/librawtls/include/rawtls/session.hpp \
                       $(top_srcdir)/librawtls/include/rawtls/spiffe.hpp \
                       $(top_srcdir)/librawtls/include/rawtls/transport.hpp \
                       context.cpp \
                       session.cpp \
                       spiffe.cpp \
                       transport.cpp

librawtls_la_LIBADD = $(OPENSSL_LIBS)
