ARG GO_VERSION=1.16
FROM golang:${GO_VERSION}-alpine

RUN apk --no-cache --no-progress add \
     bash \
     ncurses \
     curl \
     gcc \
     make \
     musl-dev \
     tar \
     ca-certificates \
     tzdata \
     linux-headers

WORKDIR /app

ENTRYPOINT ["make", "build"]