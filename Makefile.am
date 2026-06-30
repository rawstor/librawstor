SUBDIRS = librawstd \
          librawio \
          src \
          cli \
          vhost \
          ost

if ENABLE_TESTS
    SUBDIRS += tests
endif

if WITH_PYTHON3
    SUBDIRS += pyrawstor
endif


ACLOCAL_AMFLAGS = -I m4


README: $(srcdir)/README.md
	cp $(srcdir)/README.md README


ChangeLog: $(srcdir)/ChangeLog.md
	cp $(srcdir)/ChangeLog.md ChangeLog


EXTRA_DIST = ChangeLog.md \
             README.md \
             deb/python3-rawstor/compat \
             deb/python3-rawstor/rules


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
