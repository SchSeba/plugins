FROM golang:1.10 AS builder

COPY . /go/src/github.com/containernetworking/plugins

WORKDIR /go/src/github.com/containernetworking/plugins/

RUN ./build_linux.sh

FROM fedora:28

RUN mkdir -p /usr/src/containernetworking/plugins/bin

COPY --from=builder /go/src/github.com/containernetworking/plugins/bin/* /usr/src/containernetworking/plugins/bin/