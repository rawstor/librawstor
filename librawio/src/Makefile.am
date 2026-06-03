noinst_LTLIBRARIES = librawio.la


AM_CFLAGS = $(GENERIC_CFLAGS) \
            $(ASAN_CFLAGS) \
            -I$(top_srcdir)/librawio/include \
            -I$(top_srcdir)/librawstd/include \
            -I$(top_srcdir)/include

AM_CXXFLAGS = $(GENERIC_CXXFLAGS) \
              $(ASAN_CFLAGS) \
              -I$(top_srcdir)/librawio/include \
              -I$(top_srcdir)/librawstd/include \
              -I$(top_srcdir)/include

AM_LDFLAGS = $(ASAN_LDFLAGS)


librawio_la_SOURCES = $(top_srcdir)/librawio/include/rawio/queue.hpp \
                      queue.cpp \
                      rawio.cpp

librawio_la_LIBADD =


if WITH_LIBURING
    AM_CFLAGS += $(LIBURING_CFLAGS)
    AM_CXXFLAGS += $(LIBURING_CFLAGS)
    librawio_la_SOURCES += uring_buffer.cpp \
                           uring_buffer.hpp \
                           uring_queue.cpp \
                           uring_queue.hpp
    librawio_la_LIBADD += $(LIBURING_LIBS)
else
    librawio_la_SOURCES += poll_event.cpp \
                           poll_event.hpp \
                           poll_queue.cpp \
                           poll_queue.hpp \
                           poll_session.cpp \
                           poll_session.hpp
endif
