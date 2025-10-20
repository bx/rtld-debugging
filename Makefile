IMAGE=binary-fun-rtld-debugger

ifneq ($(VOLUME),)
ADDITIONAL_DOCKER_ARGS += -v $(realpath $(VOLUME)):/workspace/mnt
endif

.PHONY: $(IMAGE) build sh

build: $(IMAGE)

$(IMAGE): Dockerfile
	docker buildx build --build-arg=JOBS=$(JOBS) -t $(IMAGE) .

sh: build
	docker run --cap-add=SYS_PTRACE \
	--security-opt seccomp=unconfined \
	--user $(id -u):$(id -g) \
	$(ADDITIONAL_DOCKER_ARGS) \
	--rm -it $(IMAGE) /bin/bash
