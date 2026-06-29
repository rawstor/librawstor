build-rawstor:
	$(PYTHON) -m build

install-rawstor:
	$(PYTHON) -m pip install $(srcdir)

if ENABLE_TESTS
test:
	$(PYTHON) -m unittest
endif

clean-local:
	rm -rf $(srcdir)/build $(srcdir)/dist $(srcdir)/*.egg-info $(srcdir)/__pycache__

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

PHONY_TARGETS = install-rawstor

if ENABLE_TESTS
PHONY_TARGETS += test
endif

.PHONY: $(PHONY_TARGETS)
