build-rawstor:
	cd $(srcdir) && $(PYTHON) -m build --outdir $(builddir)/dist

install-rawstor:
	$(PYTHON) -m pip install $(srcdir)

if ENABLE_TESTS
test:
	cd $(srcdir) && $(PYTHON) -m unittest
endif

clean-local:
	rm -rf $(srcdir)/build $(srcdir)/dist $(srcdir)/*.egg-info $(srcdir)/__pycache__

all-local: build-rawstor

EXTRA_DIST = \
    rawstor/module.c \
    rawstor/rawstor.c \
    rawstor/rawstor.h \
    tests/__init__.py
    MANIFEST.in \
    setup.py \

PHONY_TARGETS = install-rawstor

if ENABLE_TESTS
PHONY_TARGETS += test
endif

.PHONY: $(PHONY_TARGETS)
