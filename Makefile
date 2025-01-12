SUBDIRS = src \
          vhost-user


define FOREACH
	for dir in $(SUBDIRS); do \
		$(MAKE) -C $${dir} $1; \
	done;
endef


all:
	$(call FOREACH,all)


clean:
	$(call FOREACH,clean)


.PHONY: all clean
