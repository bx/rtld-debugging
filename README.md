# overview

This repository holds some scripts that build a docker image for the purpose of
inspecting debugging the runtime linker/loader ld.so (& more specifically, GNU's
glibc RTLD) within gdb.

Within the built container, you can use `debug-ld.sh` script to setup a gdb
environment that hooks ld.so as it loads the binary of your choice. This script
takes care of loading symbols from your binary executable after it is loaded by
ld.so, then sets a breakpoint for _main, and it also sets a breakpoint at the
beginning of the .plt section in memory to allow to step through the runtime
linker's symbol resolution process


# setup

Requirements: docker must be installed and running and your current user must
have permissions to build and spawn docker images/containers

Next, run `make build` to build the docker image


# use

Run `make sh` to spawn a container and enter a shell. Execute:
`./debug-ld.sh ./testcase/hello-world`

to debug runtime linker/loader as it
processes a simple hello-world example binary.


Invoke:
`./debug-ld.sh <path to an executable>`

to debug the linker/loader as it processes an ELF executable of your choice.

If you execute `make sh` with a VOLUME environmental variable set, it will spawn
a container with the directory at VOLUME mounted to /workspace/mnt , e.g.,

`VOLUME=$HOME/some_directory make sh`
