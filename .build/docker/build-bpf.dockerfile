ARG ALPINE_VERSION=3.12

FROM alpine:${ALPINE_VERSION}

RUN apk add --update \
    bcc-dev \
    clang \
    musl-dev \
    llvm9 \
    linux-headers \
    make \
    bash

WORKDIR /src

ENTRYPOINT ["make", "build"]