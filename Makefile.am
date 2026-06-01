SUBDIRS = librawstd \
          librawio \
          src \
          cli \
          vhost \
          ost

if ENABLE_TESTS
    SUBDIRS += tests
endif


ACLOCAL_AMFLAGS = -I m4


README: README.md
	cp README.md README


ChangeLog: ChangeLog.md
	cp ChangeLog.md ChangeLog


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
