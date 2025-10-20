FROM debian:13.1
    LABEL org.opencontainers.image.authors="bx <bx@dartmouth.edu>"
ARG VERSION=2.42
ARG JOBS=
ENV VERSION=$VERSION

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
         curl build-essential openssl wget gzip gdb gawk \
         bison python-is-python3 gettext texinfo && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -Ums /bin/bash user && \
    mkdir /workspace /build && \
    chown -R user /workspace /build

USER user

WORKDIR /build

ENV PREFIX=/build/local

# fetch and unpack glibc soure
RUN curl -s --output glibc.tar.gz https://ftp.gnu.org/gnu/libc/glibc-$VERSION.tar.gz && \
    tar -xzf glibc.tar.gz && \
    mv glibc-$VERSION glibc && \
    rm glibc.tar.gz && \
    mkdir "$PREFIX"

# build glibc
WORKDIR /build/build

RUN ../glibc/configure -q \
       --disable-profile \
       --prefix="$PREFIX" \
       --libdir="$PREFIX/lib" \
       --libexecdir="$PREFIX/lib" \
       --enable-multi-arch && \
    make -j $JOBS && \
    make install

COPY --chown=user:user testcase /workspace/testcase
COPY --chown=user:user debug-ld.sh hook-exec-main.py /workspace/

ENV LIBC_PREFIX=/build/local
ENV LIBC_SRC=/build/glibc
ENV GLIBC_VERSION=$VERSION

WORKDIR /workspace/testcase
RUN make
WORKDIR /workspace

CMD [ "/bin/bash" ]
