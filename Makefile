LD_IMAGE=binary-fun-rtld-debugger
PATCH_IMAGE=binary-fun-elf-patcher
DOCKER_RUN_USER += --user $(shell id -u):$(shell id -g)

ifneq ($(VOLUME),)
ADDITIONAL_DOCKER_ARGS += -v $(realpath $(VOLUME)):/workspace/mnt
endif

.PHONY: $(LD_IMAGE) build sh $(PATCH_IMAGE) examples patch clean ld-samples


build: $(LD_IMAGE)

DOCKER_RUN_SAMPLES_ARGS := -v $(realpath .)/samples:/workspace/mnt -e PATCH=/app/patch.py -w /workspace


examples: $(LD_IMAGE)
	docker run $(DOCKER_RUN_USER) $(DOCKER_RUN_SAMPLES_ARGS) --rm $(LD_IMAGE) make -C mnt binaries

patch: $(PATCH_IMAGE) examples
	docker run $(DOCKER_RUN_USER) $(DOCKER_RUN_SAMPLES_ARGS)  --rm $(PATCH_IMAGE)  make -C mnt patch

$(PATCH_IMAGE): patch.Dockerfile
	docker buildx build --build-arg=JOBS=$(JOBS) -t $(PATCH_IMAGE) -f $< ./samples

clean:
	make -C samples clean


$(LD_IMAGE): Dockerfile
	docker buildx build --build-arg=JOBS=$(JOBS) -t $(LD_IMAGE) .

DOCKER_RUN_LD = docker run --cap-add=SYS_PTRACE
DOCKER_RUN_LD += --security-opt seccomp=unconfined
DOCKER_RUN_LD += $(DOCKER_RUN_USER)
DOCKER_RUN_LD += $(ADDITIONAL_DOCKER_ARGS)
ifneq ($(DEBUG_PLUGIN),)
DOCKER_RUN_LD += -v $(realpath .)/scripts/rtld-debug:/workspace/rtld-debug
endif

ld-samples: patch
	$(DOCKER_RUN_LD) $(DOCKER_RUN_SAMPLES_ARGS) --rm -it $(LD_IMAGE)  /bin/bash -c 'echo -e "\n\nsample binaries available in $PWD/mnt\nrun gdb instrumented loader loading sample binary:\n./debug-ld.sh ./mnt/hello-world" &&  /bin/bash'


sh: build
	$(DOCKER_RUN_LD) --rm -it $(LD_IMAGE) /bin/bash

debug: build
	$(DOCKER_RUN_LD) --rm -it $(LD_IMAGE) ./build-and-debug.sh $(TARGET) $(if $(TARGET),"$(TARGET_RUN_ARGS)",)
