SUBDIRS = librawstd \
          librawio \
          src \
          cli \
          vhost

if ENABLE_TESTS
    SUBDIRS += tests
endif


ACLOCAL_AMFLAGS = -I m4


README: $(srcdir)/README.md
	cp $(srcdir)/README.md README


ChangeLog: $(srcdir)/ChangeLog.md
	cp $(srcdir)/ChangeLog.md ChangeLog


EXTRA_DIST = ChangeLog.md \
             README.md


CLEANFILES = ChangeLog \
             README


if ENABLE_TESTS
test: all
	make -C librawstd test
	make -C librawio test
	make -C tests test

.PHONY: test
endif
