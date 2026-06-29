if ENABLE_TESTS
ENABLE_TESTS = yes
else
ENABLE_TESTS = no
endif

copy-sources:
	if [ "$(srcdir)" != "$(builddir)" ]; then \
	  cp -fR \
	    $(srcdir)/rawstor \
	    $(srcdir)/config.py \
	    $(srcdir)/MANIFEST.in \
	    $(srcdir)/setup.py \
	    .; \
	  if [ "x$(ENABLE_TESTS)" = "xyes" ]; then \
	    cp -fR \
	      $(srcdir)/tests \
	      .; \
	  fi \
	fi

build-rawstor: copy-sources
	$(PYTHON) -m build --outdir $(builddir)/dist

install-rawstor: build-rawstor
	$(PYTHON) -m pip install \
	  --no-deps \
	  --no-build-isolation \
	  --prefix=$(DESTDIR)$(prefix) \
	  $(builddir)/dist/*.whl

if ENABLE_TESTS
test:
	cd $(srcdir) && $(PYTHON) -m unittest
endif

clean-local:
	-rm -rf $(builddir)/dist

all-local: build-rawstor

EXTRA_DIST = \
    rawstor/module.c \
    rawstor/rawstor.c \
    rawstor/rawstor.h \
    config.py \
    MANIFEST.in \
    setup.py

if ENABLE_TESTS
EXTRA_DIST += \
    tests/__init__.py
endif

PHONY_TARGETS = copy-sources install-rawstor

if ENABLE_TESTS
PHONY_TARGETS += test
endif

.PHONY: $(PHONY_TARGETS)
