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

ARG VERSION="devel"
ARG VCS_REF="unknown"
ARG TARGETOS
ARG TARGETARCH

ENV GOOS=${TARGETOS}
ENV GOARCH=${TARGETARCH}

RUN go build -v \
  -tags netgo,osusergo \
  -ldflags "-X \"github.com/enix/x509-certificate-exporter/v3/internal.Version=${VERSION}\" \
            -X \"github.com/enix/x509-certificate-exporter/v3/internal.Revision=${VCS_REF}\" \
            -X \"github.com/enix/x509-certificate-exporter/v3/internal.BuildDateTime=$(date -u -Iseconds)\"" \
  ./cmd/x509-certificate-exporter


## Production Stage

# https://github.com/hadolint/hadolint/issues/861
# hadolint ignore=DL3029
FROM --platform=${TARGETPLATFORM:-linux/amd64} alpine:3.16.2

COPY --from=build /go/src/github.com/enix/x509-certificate-exporter/x509-certificate-exporter /x509-certificate-exporter

EXPOSE 9793/tcp

ENTRYPOINT [ "/x509-certificate-exporter" ]
