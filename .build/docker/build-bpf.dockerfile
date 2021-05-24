ARG ALPINE_VERSION=3.13.5

FROM alpine:${ALPINE_VERSION}

RUN apk add --update \
    libbpf-dev \
    bcc-dev \
    clang \
    musl-dev \
    llvm10 \
    linux-lts-dev \
    make \
    bash

WORKDIR /bpf

ENTRYPOINT ["make"]
