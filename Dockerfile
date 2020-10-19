FROM golang:1.15-alpine as build

WORKDIR $GOPATH/src/enix.io/x509-exporter

COPY go.mod go.mod

COPY go.sum go.sum

RUN go mod download

COPY internal internal

COPY cmd cmd

RUN go build ./cmd/x509-exporter

###############

FROM alpine:3.12

RUN wget -O /usr/local/bin/yq "https://github.com/mikefarah/yq/releases/download/3.4.0/yq_linux_amd64"

RUN chmod +x /usr/local/bin/yq

COPY --from=build /go/src/enix.io/x509-exporter/x509-exporter /x509-exporter

ENTRYPOINT [ "/x509-exporter" ]
