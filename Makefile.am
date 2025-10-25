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


dist-hook:
	@if test -f rpm/librawstor.spec.in; then \
	    sed -e 's/\@PACKAGE_VERSION_SHORT\@/$(PACKAGE_VERSION_SHORT)/g' \
	        -e 's/\@PACKAGE_RELEASE\@/$(PACKAGE_RELEASE)/g' \
	        rpm/librawstor.spec.in > $(distdir)/rpm/librawstor.spec; \
	fi


if ENABLE_TESTS
test: all
	make -C librawstorstd test
	make -C librawstorio test
	make -C tests test

.PHONY: test
endif
