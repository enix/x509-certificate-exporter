## Build Stage

ARG OS="linux"
ARG ARCH="amd64"

FROM --platform=${OS}/${ARCH} golang:1.16 as build

ARG OS
ARG ARCH
ARG VERSION="0.0.0"

WORKDIR /opt

COPY . .

RUN CGO_ENABLED=0 GOOS=${OS} GOARCH=${ARCH} go build -ldflags "-s -X \"enix.io/x509-certificate-exporter/internal.Version=${VERSION}\"" ./cmd/x509-certificate-exporter

## Production Stage

LABEL maintainer="Enix <no-reply@enix.fr>" \
      org.opencontainers.image.title="X.509 Certificate Exporter" \
      org.opencontainers.image.description="A Prometheus exporter for certificates focusing on expiration monitoring." \
      org.opencontainers.image.url="https://github.com/enix/x509-certificate-exporter" \
      org.opencontainers.image.sources="https://github.com/enix/x509-certificate-exporter/blob/master/Dockerfile" \
      org.opencontainers.image.documentation="https://github.com/enix/x509-certificate-exporter/blob/master/README.md" \
      org.opencontainers.image.authors="Enix <no-reply@enix.fr>" \
      org.opencontainers.image.licenses="MIT"

FROM scratch

COPY --from=build /opt/x509-certificate-exporter /x509-certificate-exporter

EXPOSE 9793/tcp

ENTRYPOINT [ "/x509-certificate-exporter" ]

LABEL org.opencontainers.image.version="$VERSION"

