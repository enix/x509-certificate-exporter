ARG OS="linux"

ARG ARCH="amd64"

FROM --platform=${OS}/${ARCH} golang:1.15-alpine as build

ARG OS

ARG ARCH

WORKDIR $GOPATH/src/enix.io/x509-certificate-exporter

COPY go.mod go.mod

COPY go.sum go.sum

RUN go mod download

COPY internal internal

COPY cmd cmd

ENV GOOS=${OS}

ENV GOARCH=${ARCH}

RUN go build ./cmd/x509-certificate-exporter

###############

FROM --platform=${OS}/${ARCH} alpine:3.13

COPY --from=build /go/src/enix.io/x509-certificate-exporter/x509-certificate-exporter /x509-certificate-exporter

ENTRYPOINT [ "/x509-certificate-exporter" ]
