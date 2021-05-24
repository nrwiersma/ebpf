ARG GO_VERSION=1.16
ARG LINT_VERSION=v1.40.1
FROM golang:${GO_VERSION}-alpine

RUN apk --no-cache --no-progress add \
     make \
     ca-certificates \
     curl \
     tzdata

RUN curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin ${LINT_VERSION}

WORKDIR /app

CMD ["make", "build"]
