bin_PROGRAMS = rawstor-ost

AM_CXXFLAGS = $(GENERIC_CXXFLAGS) \
              $(ASAN_CFLAGS) \
              -I$(top_srcdir)/librawstorstd/include \
              -I$(top_srcdir)/include

AM_LDFLAGS = $(ASAN_LDFLAGS)


rawstor_ost_SOURCES = main.cpp \
                      server.cpp \
                      server.hpp \
                      session.cpp \
                      session.hpp

rawstor_ost_LDADD = $(top_builddir)/src/librawstor.la -lstdc++
