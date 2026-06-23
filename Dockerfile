# Requires Go 1.25+ (driven by modernc.org/sqlite dependency).
# golang:alpine tracks the latest stable release.

# ── Build stage ───────────────────────────────────────────────
FROM golang:alpine AS builder

WORKDIR /build

# Cache the module download layer separately from source changes.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO_ENABLED=0: modernc.org/sqlite is pure Go — no C toolchain needed.
# -ldflags="-s -w": strip debug info to reduce binary size (~40%).
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o s-hole .

# ── Runtime stage ─────────────────────────────────────────────
FROM alpine:latest

# ca-certificates: required for HTTPS blocklist downloads.
# tzdata: optional, allows log timestamps in local time.
RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app
COPY --from=builder /build/s-hole .
COPY config.yaml .

# DNS (UDP + TCP) and admin UI.
EXPOSE 53/udp
EXPOSE 53/tcp
EXPOSE 8080/tcp

# Mount /app to persist config.yaml, blocklist cache, and queries.db
# across container restarts.
VOLUME ["/app"]

ENTRYPOINT ["./s-hole"]
CMD ["-config", "/app/config.yaml"]
