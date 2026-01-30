#!/usr/bin/env sh
DIR="$(realpath $(dirname $0))"

if [ $# -lt 1 ]; then
    ELF="$(realpath $DIR/../testcase/hello-world)"

else
    ELF="$(realpath $1)"
    shift
fi


# set directory containg source for the libc we are debugging
if [ -z "$LIBC_SRC" ]; then
    LIBC_SRC=/build/binutils
fi

# set install prefix of libc we are debugging
if [ -z "$LIBC_PREFIX" ]; then
    LIBC_PREFIX=/build/local
fi


# build object file with elf struct definitions to aid debugging if not present
if [ ! -f "$DIR/rtld-debug/structs.o" ]; then
    CFLAGS="-I $LIBC_PREFIX/include" make -C "$DIR/rtld-debug"
fi


# calculate path to ld.so we will be debugging
LOADER_BIN="$(basename $(ls $LIBC_PREFIX/lib/ld-*so* | head -n 1))"
#echo gdb -ex "source $DIR/hook-exec-main.py" -ex "source $DIR/rtld-debug/rtld-debug.py" -ex "elf init $ELF" -ex 'break _start' -ex 'break _dl_map_object_from_fd' -ex 'break _dl_relocate_object' -ex "directory $(dirname $ELF)" -ex "run --library-path $LIBC_PREFIX/lib $ELF \"$@\"" "$LIBC_PREFIX/lib/$LOADER_BIN"
# run gdb, loading various scripts to debug rtld
gdb -ex "source $DIR/hook-exec-main.py" -ex "source $DIR/rtld-debug/rtld-debug.py" -ex "elf init $ELF" -ex 'break _start' -ex "elf break-load $(realpath $ELF)" -ex "elf break-reloc $(realpath $ELF)"  -ex "directory $(dirname $ELF)" -ex "run --library-path $LIBC_PREFIX/lib $ELF \"$@\"" "$LIBC_PREFIX/lib/$LOADER_BIN"
