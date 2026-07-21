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


NEWS: $(srcdir)/NEWS.md
	cp $(srcdir)/NEWS.md NEWS


deb/librawstor/changelog: $(srcdir)/ChangeLog.md $(srcdir)/.github/tools/deb-changelog.sh
	{ \
	  echo "librawstor ($(PACKAGE_VERSION_SHORT)) UNRELEASED; urgency=medium"; \
	  echo; \
	  $(srcdir)/.github/tools/deb-changelog.sh body $(srcdir)/ChangeLog.md; \
	  echo; \
	  echo " -- Vasily Stepanov <vasily.stepanov@gmail.com>  $$($(srcdir)/.github/tools/deb-changelog.sh date $(srcdir)/ChangeLog.md)"; \
	  echo; \
	  $(srcdir)/.github/tools/deb-changelog.sh history librawstor $(srcdir)/ChangeLog.md; \
	} > $@


deb/python3-rawstor/changelog: $(srcdir)/ChangeLog.md $(srcdir)/.github/tools/deb-changelog.sh
	{ \
	  echo "rawstor ($(PACKAGE_VERSION_SHORT)) UNRELEASED; urgency=medium"; \
	  echo; \
	  $(srcdir)/.github/tools/deb-changelog.sh body $(srcdir)/ChangeLog.md; \
	  echo; \
	  echo " -- Vasily Stepanov <vasily.stepanov@gmail.com>  $$($(srcdir)/.github/tools/deb-changelog.sh date $(srcdir)/ChangeLog.md)"; \
	  echo; \
	  $(srcdir)/.github/tools/deb-changelog.sh history rawstor $(srcdir)/ChangeLog.md; \
	} > $@


EXTRA_DIST = deb/librawstor/compat \
             deb/librawstor/format \
             deb/librawstor/librawstor.install \
             deb/librawstor/librawstor-dev.install \
             deb/librawstor/rawstor-ost.install \
             deb/librawstor/rawstor-ost.postinst \
             deb/librawstor/rawstor-ost.prerm \
             deb/librawstor/rules \
             deb/python3-rawstor/compat \
             deb/python3-rawstor/format \
             deb/python3-rawstor/rules \
             etc/systemd/system/rawstor-ost.service \
             .github/tools/deb-changelog.sh \
             ChangeLog.md \
             README.md \
             NEWS.md


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
	make -C tests test
	@if [ "x$(WITH_PYTHON3)" = "xyes" ]; then \
	  make -C pyrawstor test; \
	fi

.PHONY: test
endif
