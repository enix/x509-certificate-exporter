FROM --platform=$BUILDPLATFORM golang:1.24.4 AS base
WORKDIR /app

FROM --platform=$BUILDPLATFORM cosmtrek/air:v1.62.0 AS air

FROM base AS dev
ARG USER_ID=1000
ARG GROUP_ID=1000
RUN groupadd -g ${GROUP_ID} air \
    && useradd -l -u ${USER_ID} -g air air \
    && install -d -m 0700 -o air -g air /home/air
USER ${USER_ID}:${GROUP_ID}
COPY --from=air /go/bin/air /go/bin/air
CMD [ "/go/bin/air" ]

FROM base AS build
COPY go.mod go.mod
COPY go.sum go.sum
RUN go mod download -x
COPY internal internal
# COPY pkg pkg
COPY cmd cmd
ARG TARGETOS
ARG TARGETARCH
ARG VERSION="devel"
ARG VCS_REF="unknown"
ENV GOOS=${TARGETOS}
ENV GOARCH=${TARGETARCH}
RUN go build -v -a -buildvcs=false \
    -tags netgo,osusergo \
    -ldflags " \
    -X \"github.com/enix/x509-certificate-exporter/v3/internal.Version=${VERSION}\" \
    -X \"github.com/enix/x509-certificate-exporter/v3/internal.Revision=${VCS_REF}\" \
    -X \"github.com/enix/x509-certificate-exporter/v3/internal.BuildDateTime=$(date -u -Iseconds)\" \
    " \
    -o /x509-certificate-exporter \
    ./cmd/x509-certificate-exporter
FROM scratch AS distroless
COPY --from=build --chown=0:0 --chmod=0555 /x509-certificate-exporter /x509-certificate-exporter
USER 65534:65534
EXPOSE 9793/tcp
ENTRYPOINT [ "/x509-certificate-exporter" ]

FROM cgr.dev/chainguard/wolfi-base:latest@sha256:08a4c4fc8583c217c853fda751f08495530d105c361b714f6d33ae3edb5ec11c
COPY --from=build --chown=0:0 --chmod=0555 /x509-certificate-exporter /x509-certificate-exporter
USER nobody:nobody
EXPOSE 9793/tcp
ENTRYPOINT [ "/x509-certificate-exporter" ]
