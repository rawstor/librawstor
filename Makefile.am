SUBDIRS = librawstd \
          librawio \
          src \
          cli \
          vhost

if ENABLE_TESTS
    SUBDIRS += tests
endif

if ENABLE_OST_BACKEND
    SUBDIRS += ost
endif

if WITH_PYTHON3
    SUBDIRS += pyrawstor
endif


ACLOCAL_AMFLAGS = -I m4


README: $(srcdir)/README.md
	cp $(srcdir)/README.md README


ChangeLog: $(srcdir)/ChangeLog.md
	cp $(srcdir)/ChangeLog.md ChangeLog


EXTRA_DIST = deb/librawstor/compat \
             deb/librawstor/format \
             deb/librawstor/librawstor.postinst \
             deb/librawstor/librawstor.prerm \
             deb/librawstor/rules \
             deb/python3-rawstor/compat \
             deb/python3-rawstor/format \
             deb/python3-rawstor/rules \
             deb/rawstor-ost/compat \
             deb/rawstor-ost/format \
             deb/rawstor-ost/rules \
             ChangeLog.md \
             README.md

if ENABLE_OST_BACKEND
EXTRA_DIST += etc/systemd/system/rawstor-ost.service
endif
             

CLEANFILES = ChangeLog \
             README


if ENABLE_TESTS

if WITH_PYTHON3
WITH_PYTHON3 = yes
else
WITH_PYTHON3 = no
endif

test: all
	make -C librawstd test
	make -C librawio test
	make -C tests test
	@if [ "x$(WITH_PYTHON3)" = "xyes" ]; then \
	  make -C pyrawstor test; \
	fi

.PHONY: test
endif
