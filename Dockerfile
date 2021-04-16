FROM scratch

COPY ./agent .
COPY ./net .

EXPOSE 80