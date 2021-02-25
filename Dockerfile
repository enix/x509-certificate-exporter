## Build Stage

ARG OS="linux"
ARG ARCH="amd64"

FROM --platform=${OS}/${ARCH} golang:1.16-alpine as build

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

ARG VERSION="0.0.0"

RUN go build -ldflags "-X \"enix.io/x509-certificate-exporter/internal.Version=${VERSION}\"" ./cmd/x509-certificate-exporter


## Production Stage

LABEL maintainer="Enix <no-reply@enix.fr>" \
      org.opencontainers.image.title="X.509 Certificate Exporter" \
      org.opencontainers.image.description="A Prometheus exporter for certificates focusing on expiration monitoring." \
      org.opencontainers.image.url="https://github.com/enix/x509-certificate-exporter" \
      org.opencontainers.image.sources="https://github.com/enix/x509-certificate-exporter/blob/master/Dockerfile" \
      org.opencontainers.image.documentation="https://github.com/enix/x509-certificate-exporter/blob/master/README.md" \
      org.opencontainers.image.authors="Enix <no-reply@enix.fr>" \
      org.opencontainers.image.licenses="MIT"

FROM --platform=${OS}/${ARCH} alpine:3.13

COPY --from=build /go/src/enix.io/x509-certificate-exporter/x509-certificate-exporter /x509-certificate-exporter

ENTRYPOINT [ "/x509-certificate-exporter" ]

#ARG VCS_REF
#ARG BUILD_DATE
LABEL org.opencontainers.image.version="$VERSION"
#      org.opencontainers.image.revision="$VCS_REF" \
#      org.opencontainers.image.created="$BUILD_DATE"
