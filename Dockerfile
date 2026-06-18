FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS build

WORKDIR /src
# go.mod + go.sum: this app uses the AWS SDK (ADR-073 conformance checks), so the lockfile is copied first to
# cache dependency download as its own layer.
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/

# Cross-compile to the target arch (buildx sets TARGETOS/TARGETARCH) so multi-arch builds run on the native
# (amd64) toolchain with no QEMU emulation — Go cross-compiles for free.
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags="-s -w" -o /app ./cmd/server

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /app /app

EXPOSE 8080

# Run as the distroless nonroot user explicitly (uid:gid 65532). The base already defaults to nonroot,
# but an explicit USER makes it auditable and satisfies the image-runs-as-root scanners
# (Trivy DS-0002 / Semgrep missing-user-entrypoint).
USER 65532:65532

ENTRYPOINT ["/app"]
