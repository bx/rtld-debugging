FROM python:3.13-bookworm
    LABEL org.opencontainers.image.authors="bx <bx@dartmouth.edu>"
ARG VERSION=2.42
ARG JOBS=
ENV VERSION=$VERSION

WORKDIR /app
RUN apt-get install make
RUN useradd -Ums /bin/bash user && \
    mkdir /workspace /build && \
    chown -R user /app

RUN pip install --no-cache-dir lief pyelftools click

USER user


COPY --chown=user:user patch.py /app

WORKDIR /app


CMD [ "/bin/bash" ]
