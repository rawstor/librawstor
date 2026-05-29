SUBDIRS = librawstd \
          librawio \
          src \
          cli \
          vhost

if ENABLE_TESTS
    SUBDIRS += tests
endif


ACLOCAL_AMFLAGS = -I m4


README: README.md
	cp README.md README


EXTRA_DIST = README.md


CLEANFILES = README


if ENABLE_TESTS
test: all
	make -C librawstd test
	make -C librawio test
	make -C tests test

.PHONY: test
endif
