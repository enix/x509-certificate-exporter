## Build Stage

# https://github.com/hadolint/hadolint/issues/861
# hadolint ignore=DL3029
FROM --platform=${BUILDPLATFORM:-linux/amd64} golang:1.18.6-alpine as build

WORKDIR $GOPATH/src/github.com/enix/x509-certificate-exporter

COPY go.mod go.mod
COPY go.sum go.sum

RUN go mod download

COPY internal internal
COPY cmd cmd

ARG VERSION="0.0.0"
ARG VCS_REF="unknown"
ARG BUILD_DATE="unknown"
ARG TARGETOS
ARG TARGETARCH

ENV GOOS=${TARGETOS}
ENV GOARCH=${TARGETARCH}

RUN go build \
  -tags netgo,osusergo \
  -ldflags "-X \"github.com/enix/x509-certificate-exporter/v3/internal.Version=${VERSION}\" \
            -X \"github.com/enix/x509-certificate-exporter/v3/internal.CommitHash=${VCS_REF}\" \
            -X \"github.com/enix/x509-certificate-exporter/v3/internal.BuildDateTime=${BUILD_DATE}\"" \
  ./cmd/x509-certificate-exporter


## Production Stage

# https://github.com/hadolint/hadolint/issues/861
# hadolint ignore=DL3029
FROM --platform=${TARGETPLATFORM:-linux/amd64} alpine:3.16.2

ARG VERSION="0.0.0"
ARG VCS_REF="unknown"
ARG BUILD_DATE="unknown"

LABEL maintainer="Enix <contact@enix.fr>" \
      org.opencontainers.image.title="X.509 Certificate Exporter" \
      org.opencontainers.image.description="A Prometheus exporter for certificates focusing on expiration monitoring." \
      org.opencontainers.image.url="https://github.com/enix/x509-certificate-exporter" \
      org.opencontainers.image.sources="https://github.com/enix/x509-certificate-exporter/blob/master/Dockerfile" \
      org.opencontainers.image.documentation="https://github.com/enix/x509-certificate-exporter/blob/master/README.md" \
      org.opencontainers.image.authors="Enix <contact@enix.fr>" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}"

COPY --from=build /go/src/github.com/enix/x509-certificate-exporter/x509-certificate-exporter /x509-certificate-exporter

EXPOSE 9793/tcp

ENTRYPOINT [ "/x509-certificate-exporter" ]
