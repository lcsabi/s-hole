# Requires Go 1.26 (the go.mod go line). The builder image is pinned to that
# release, so the image and the release archives build with the same Go
# version; Dependabot proposes the next one.

# ── Build stage ───────────────────────────────────────────────
# The builder runs on the build host's platform and cross-compiles for the
# target platform. Go needs no emulation to cross-compile, so a multi-arch
# build does not run the compiler under QEMU.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder

WORKDIR /build

# Cache the module download layer separately from source changes.
COPY go.mod go.sum ./
RUN go mod download

# libcap-utils provides setcap (see below). It is installed before the source
# is copied, so a source change does not fetch it again.
RUN apk add --no-cache libcap-utils

COPY . .

# Build-time version metadata. Callers can override with --build-arg.
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
# Set by BuildKit for each target platform.
ARG TARGETOS TARGETARCH TARGETVARIANT

# CGO_ENABLED=0: modernc.org/sqlite is pure Go, so no C toolchain is needed.
# -trimpath: the binary does not carry the build paths.
# -ldflags="-s -w": strip debug info to reduce binary size (~40%).
# Version metadata is injected via -X so the binary can report its identity
# at runtime (use `s-hole -version`).
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH GOARM=${TARGETVARIANT#v} go build -trimpath \
    -ldflags="-s -w \
      -X 'github.com/lcsabi/s-hole/internal/version.Version=${VERSION}' \
      -X 'github.com/lcsabi/s-hole/internal/version.Commit=${COMMIT}' \
      -X 'github.com/lcsabi/s-hole/internal/version.BuildDate=${BUILD_DATE}'" \
    -o s-hole ./cmd/s-hole

# The file capability lets s-hole bind port 53 (and 853 for DoT) as an
# unprivileged user, also with --network host. Set it here, in the build
# stage: BuildKit's COPY keeps it. In the runtime stage, setcap would change
# the file that the COPY layer added, and the image would store the binary
# twice (CL 103).
RUN setcap cap_net_bind_service=+ep s-hole

# ── Runtime stage ─────────────────────────────────────────────
FROM alpine:3.24

# ca-certificates: required for HTTPS blocklist downloads and DoH upstreams.
# Container logs default to UTC (matches log/slog), so tzdata is not
# pulled in.
RUN apk add --no-cache ca-certificates

# The binary lives on PATH, NOT in /app. /app is declared a VOLUME and is
# meant to be bind-mounted to a host data directory; a bind mount replaces the
# directory's contents, so anything under /app (a binary included) is shadowed
# at runtime. Keeping s-hole in /usr/local/bin keeps it reachable regardless of
# what the operator mounts over /app (b/039).
COPY --from=builder /build/s-hole /usr/local/bin/s-hole

# s-hole runs as an unprivileged user (65532), not root (b/087). The binary
# carries the file capability from the build stage; NET_BIND_SERVICE is in
# Docker's default capability set.
RUN addgroup -S -g 65532 s-hole \
 && adduser -S -D -H -u 65532 -G s-hole -s /sbin/nologin s-hole

WORKDIR /app
# Baked-in default config, used only when /app is NOT bind-mounted. When an
# operator mounts a host data directory over /app, they supply their own
# /app/config.yaml (see the Docker section in README.md). The mounted directory
# must belong to user 65532 (chown -R 65532:65532 on the host).
COPY --chown=65532:65532 config.yaml .
RUN chown 65532:65532 /app && chmod 0700 /app

# DNS (UDP + TCP), DNS over TLS (off unless dns.dot_listen is set), and the
# admin UI.
EXPOSE 53/udp
EXPOSE 53/tcp
EXPOSE 853/tcp
EXPOSE 8080/tcp

# Mount /app to keep config.yaml, the blocklist cache, and a query database
# (when query_log.database is on) across container restarts.
VOLUME ["/app"]

USER 65532:65532

# Healthy once the admin server answers /readyz (the block set is loaded).
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD ["s-hole", "-healthcheck", "-config", "/app/config.yaml"]

ENTRYPOINT ["s-hole"]
CMD ["-config", "/app/config.yaml"]
