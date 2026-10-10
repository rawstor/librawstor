noinst_LTLIBRARIES = librawthread.la


AM_CXXFLAGS = $(GENERIC_CXXFLAGS) \
              $(ASAN_CFLAGS) \
              -I$(top_srcdir)/librawthread/include \
              -I$(top_srcdir)/librawio/include \
              -I$(top_srcdir)/librawstd/include \
              -I$(top_srcdir)/include

AM_LDFLAGS = $(ASAN_LDFLAGS)


librawthread_la_SOURCES = $(top_srcdir)/librawthread/include/rawthread/condition.hpp \
                          $(top_srcdir)/librawthread/include/rawthread/lock.hpp \
                          $(top_srcdir)/librawthread/include/rawthread/wake.hpp \
                          condition.cpp \
                          lock.cpp \
                          wake.cpp
