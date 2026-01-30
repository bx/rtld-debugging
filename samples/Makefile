
CFLAGS=-g

BINARIES := hello-world exec-hello-world exec-bash hello-world-rw exec-filter
PATCH ?= ./patch.py

all: $(BINARIES) patch

binaries: $(BINARIES)

hello-world: hello-world.c
	$(CC) $(CFLAGS) $< -o $@

hello-world.o: hello-world.c

exec-filter: exec-filter.c

hello-world-rw: hello-world-rw.c

exec-bash: exec-bash.c

exec-hello-world: exec-hello-world.c

exec-filter.patch-printf : exec-filter
	python3 $(PATCH) -i $< patch-printf  -o $@

exec-filter.patch-printf-sneaky : exec-filter
	python3 $(PATCH) -i $< patch-printf --sneaky  -o $@

hello-world-rw.indirect-value: hello-world-rw
	python3 $(PATCH) -i $< indirect-value  -o $@

hello-world.noop: hello-world
	python3 $(PATCH) -i $< noop  -o $@

hello-world-rw.noop: hello-world-rw
	python3 $(PATCH) -i $< noop  -o $@

exec-filter.noop: exec-filter
	python3 $(PATCH) -i $< noop  -o $@

hello-world.direct-address-simple: hello-world
	python3 $(PATCH) -i $< direct-address -s  -o $@

hello-world.direct-address: hello-world
	python3 $(PATCH) -i $< direct-address  -o $@

hello-world-rw.copy: hello-world-rw
	python3 $(PATCH) -i $< copy  -o $@


PATCHED = exec-filter.patch-printf-sneaky exec-filter.patch-printf \
	hello-world-rw.indirect-value hello-world.noop hello-world-rw.noop \
	exec-filter.noop hello-world.direct-address \
	hello-world.direct-address-simple hello-world-rw.copy


patch: $(PATCHED)

.PHONY: clean patch all binaries

define newline


endef

clean:
	$(foreach P,$(PATCHED),-@rm $P $(newline))
	-@rm hello-world
	-@rm exec-filter
	-@rm hello-world-rw
