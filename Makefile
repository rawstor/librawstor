SUBDIRS = src \
          cli \
          vu \
          tests


define FOREACH
    for dir in $(SUBDIRS); do \
        $(MAKE) -C $${dir} $1 || exit 1; \
    done;
endef


all:
	$(call FOREACH,all)


test: all
	$(MAKE) -C tests test


clean:
	$(call FOREACH,clean)


.PHONY: all clean test
