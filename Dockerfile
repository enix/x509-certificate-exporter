ARG OS="linux"

ARG ARCH="amd64"

FROM --platform=${OS}/${ARCH} golang:1.15-alpine as build

ARG OS

ARG ARCH

WORKDIR $GOPATH/src/enix.io/x509-exporter

COPY go.mod go.mod

COPY go.sum go.sum

RUN go mod download

COPY internal internal

COPY cmd cmd

ENV GOOS=${OS}

ENV GOARCH=${ARCH}

RUN go build ./cmd/x509-exporter

###############

FROM --platform=${OS}/${ARCH} enix/yq:3

COPY --from=build /go/src/enix.io/x509-exporter/x509-exporter /x509-exporter

ENTRYPOINT [ "/x509-exporter" ]
