FROM alpine:3.12

COPY ./agent .
COPY ./net .

EXPOSE 80