bin_PROGRAMS = rawstor-cli

AM_CFLAGS = $(GENERIC_CFLAGS) \
            $(ASAN_CFLAGS) \
            -I$(top_srcdir)/librawstd/include \
            -I$(top_srcdir)/librawio/include \
            -I$(top_srcdir)/include

AM_CXXFLAGS = $(GENERIC_CXXFLAGS) \
              $(ASAN_CFLAGS) \
              -I$(top_srcdir)/librawstd/include \
              -I$(top_srcdir)/librawio/include \
              -I$(top_srcdir)/include

AM_LDFLAGS = $(ASAN_LDFLAGS)


rawstor_cli_SOURCES = create.c \
                      create.h \
                      main.c \
                      remove.c \
                      remove.h \
                      show.c \
                      show.h \
                      testio.c \
                      testio.h \
                      units.c \
                      units.h \
                      uri.cpp \
                      uri.h

rawstor_cli_LDADD = $(top_builddir)/src/librawstor.la -lstdc++
