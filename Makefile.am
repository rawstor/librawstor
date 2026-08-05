SUBDIRS = librawstd \
          librawio \
          src \
          cli \
          vhost \
          vhost-qemu

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


NEWS: $(srcdir)/NEWS.md
	cp $(srcdir)/NEWS.md NEWS


deb/librawstor/changelog: $(srcdir)/ChangeLog.md $(srcdir)/.github/tools/deb-changelog.sh
	MAINTAINER="$(MAINTAINER)" $(srcdir)/.github/tools/deb-changelog.sh librawstor $(PACKAGE_VERSION_SHORT) $(PACKAGE_VERSION) $(srcdir)/ChangeLog.md $(srcdir)/changelog-authors.tsv > $@


deb/python3-rawstor/changelog: $(srcdir)/ChangeLog.md $(srcdir)/.github/tools/deb-changelog.sh
	MAINTAINER="$(MAINTAINER)" $(srcdir)/.github/tools/deb-changelog.sh rawstor $(PACKAGE_VERSION_SHORT) $(PACKAGE_VERSION) $(srcdir)/ChangeLog.md $(srcdir)/changelog-authors.tsv > $@


EXTRA_DIST = deb/librawstor/compat \
             deb/librawstor/format \
             deb/librawstor/librawstor.install \
             deb/librawstor/librawstor.links \
             deb/librawstor/librawstor-dev.install \
             deb/librawstor/rawstor-ost.install \
             deb/librawstor/rawstor-ost.postinst \
             deb/librawstor/rawstor-ost.prerm \
             deb/librawstor/rules \
             deb/python3-rawstor/compat \
             deb/python3-rawstor/format \
             deb/python3-rawstor/rules \
             systemd/rawstor-ost.service \
             systemd/rawstor-vhost@.service \
             .github/tools/deb-changelog.sh \
             ChangeLog.md \
             README.md \
             NEWS.md \
             changelog-authors.tsv


CLEANFILES = ChangeLog \
             README \
             NEWS \
             deb/librawstor/changelog \
             deb/python3-rawstor/changelog


if ENABLE_TESTS

if WITH_PYTHON3
WITH_PYTHON3 = yes
else
WITH_PYTHON3 = no
endif

test: all
	make -C librawstd test
	make -C librawio test
	make -C vhost test
	make -C tests test
	@if [ "x$(WITH_PYTHON3)" = "xyes" ]; then \
	  make -C pyrawstor test; \
	fi

.PHONY: test
endif
