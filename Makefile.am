SUBDIRS = librawstorstd \
          librawstorio \
          src \
          cli \
          vu

if ENABLE_TESTS
    SUBDIRS += tests
endif


ACLOCAL_AMFLAGS = -I m4


README: README.md
	cp README.md README


CLEANFILES = README


if ENABLE_TESTS
test: all
	make -C librawstorstd test
	make -C librawstorio test
	make -C tests test

.PHONY: test
endif
