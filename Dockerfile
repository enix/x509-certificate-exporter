ARG OS="linux"

ARG ARCH="amd64"

ARG YQ="3.4.0"

FROM --platform=${OS}/${ARCH} golang:1.15-alpine as build

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

FROM --platform=${OS}/${ARCH} alpine:3.12

ARG OS

ARG ARCH

ARG YQ

RUN wget -O /usr/local/bin/yq "https://github.com/mikefarah/yq/releases/download/${YQ}/yq_${OS}_${ARCH}"

RUN chmod +x /usr/local/bin/yq

COPY --from=build /go/src/enix.io/x509-exporter/x509-exporter /x509-exporter

ENTRYPOINT [ "/x509-exporter" ]
