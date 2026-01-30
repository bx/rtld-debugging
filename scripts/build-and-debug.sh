#!/usr/bin/env sh

USAGE="Usage: $(basename $0) [exectable name (defaults to hello-world)]"
usage() {
  cat <<EOF
Usage: $(basename "${BASH_SOURCE[0]}") [-h] [-v] [-b bi] [-d dir] [-- binary_argv]"

Wrapper script intended to be run in rtld-debugging docker container that
builds an executable to be loaded by an instrumented ld.so and then sets up
a gdb environment to inspect the runtime as the executable is loaded and run.

Available options:
-h, --help      Print this help and exit
-v, --verbose   Print script debug info
-b, --bin       Name of binary to build within [dir]
                     default value: hello-world
-b, --dir       Path do directory containing binary source
                     and its Makefile that builds binary [bin],
                     default value: testcase
--              Everything that follows this is treated as arguments
                     to be passed to binary as it's run under and
                     instrumented ld.sh


EOF
}

msg() {
  echo >&2 -e "${1-}"
}

die() {
  local msg="$1"
  local code="${2-1}" # default exit status 1
  msg "$msg"
  help
  exit "$code"
}

SCRIPT_DIR="$(dirname $(realpath $0))"

set -e


BIN=hello-world
D=testcase

while :; do
    case "${1-}" in
        -h | --help) usage ;;
        -v | --verbose) set -x ;;
        -b | --bin)
            BIN="${2-}"
            shift
            ;;
        -d | --dir)
            D="${2-}"
            shift
            ;;
        -- ) shift # remaining arguments are for binary
             break
             ;;
        -?*) die "Unknown option: $1" ;;
        *) break;;
    esac
    shift
done

cd "$D"

# if has makefile then use it to bulid binary
if [ -f Makefile ]; then
    if [ -f "$BIN" ]; then
        # remove before rebuilding
        make clean || rm "$BIN"
    fi
    make "$BIN"
fi

# pass binary and its arguments to debug-ld.sh to setup ld.so environment in gdb
"$SCRIPT_DIR"/debug-ld.sh "$BIN" "$@"
