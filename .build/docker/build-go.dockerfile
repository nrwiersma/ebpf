ARG GO_VERSION=1.16
FROM golang:${GO_VERSION}-alpine

RUN apk --no-cache --no-progress add \
     make \
     ca-certificates \
     tzdata

WORKDIR /app

ENTRYPOINT ["make", "build"]