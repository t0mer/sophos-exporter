# Multi-stage build: the Go toolchain runs on the NATIVE build platform
# (--platform=$BUILDPLATFORM) and cross-compiles the static, CGO-free binary to
# the target arch via GOOS/GOARCH/GOARM — no QEMU emulation of the build. The
# final image is scratch. Supports linux/amd64, linux/arm64 and linux/arm/v7.
#
# No CA certificates are copied: the exporter makes no outbound TLS calls (SNMP
# is UDP; /metrics and /healthz are plain HTTP), so scratch stays tiny.
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS builder
ENV GOTOOLCHAIN=local
ENV CGO_ENABLED=0
WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download
COPY . .

ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown

RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} GOARM=${TARGETVARIANT#v} \
    go build -trimpath \
      -ldflags="-s -w \
        -X github.com/t0mer/sophos-exporter/internal/version.Version=${VERSION} \
        -X github.com/t0mer/sophos-exporter/internal/version.Commit=${COMMIT} \
        -X github.com/t0mer/sophos-exporter/internal/version.Date=${DATE}" \
    -o /sophos-exporter ./cmd/sophos-exporter

FROM scratch
COPY --from=builder /sophos-exporter /sophos-exporter

EXPOSE 9835
USER 65534

# scratch has no shell, so the healthcheck runs the binary's own subcommand,
# which does an internal GET to /healthz and exits 0 (healthy) / 1 (unhealthy).
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/sophos-exporter", "healthcheck"]

ENTRYPOINT ["/sophos-exporter"]
