noinst_LTLIBRARIES = librawstorio.la


AM_CFLAGS = $(GENERIC_CFLAGS) \
            $(ASAN_CFLAGS) \
            -I$(top_srcdir)/librawstorio/include \
            -I$(top_srcdir)/librawstorstd/include \
            -I$(top_srcdir)/include

AM_CXXFLAGS = $(GENERIC_CXXFLAGS) \
              $(ASAN_CFLAGS) \
              -I$(top_srcdir)/librawstorstd/include \
              -I$(top_srcdir)/librawstorio/include \
              -I$(top_srcdir)/include

AM_LDFLAGS = $(ASAN_LDFLAGS)


librawstorio_la_SOURCES = $(top_srcdir)/librawstorio/include/rawstorio/queue.hpp \
                          $(top_srcdir)/librawstorio/include/rawstorio/task.hpp \
                          queue.cpp \
                          task.cpp

librawstorio_la_LIBADD =


if WITH_LIBURING
    AM_CFLAGS += $(LIBURING_CFLAGS)
    AM_CXXFLAGS += $(LIBURING_CFLAGS)
    librawstorio_la_SOURCES += uring_buffer.cpp \
                               uring_buffer.hpp \
                               uring_queue.cpp \
                               uring_queue.hpp
    librawstorio_la_LIBADD += $(LIBURING_LIBS)
else
    librawstorio_la_SOURCES += poll_event.cpp \
                               poll_event.hpp \
                               poll_queue.cpp \
                               poll_queue.hpp \
                               poll_session.cpp \
                               poll_session.hpp
endif
