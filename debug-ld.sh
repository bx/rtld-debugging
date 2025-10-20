#!/usr/bin/env sh
DIR="$(realpath $(dirname $0))"
if [ $# -lt 1 ]; then
    ELF="$DIR/testcase/hello-world"

else
    ELF="$(realpath $1)"
fi




# [[ -z "$LIBC_PREFIX" ]] && LIBC_PREFIX=/build/local
if [ -z "$LIBC_SRC" ]; then
    LIBC_SRC=/build/binutils
fi

LOADER_BIN=$(basename $(ls $LIBC_PREFIX/lib/ld-*so* | head))
gdb -ex "source $DIR/hook-exec-main.py" -ex "break _start" -ex "run --library-path $LIBC_PREFIX/lib $ELF" "$LIBC_PREFIX/lib/$LOADER_BIN"
