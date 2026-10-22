# Gash Dockerfile
# Multi-stage build for minimal final image

# Build stage
FROM golang:1.27-alpine AS builder

RUN apk add --no-cache git make

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -trimpath \
    -ldflags="-s -w -X main.version={{.Version}}" \
    -o /gash \
    ./cmd/gash

# Final stage
FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /gash /gash

# Metadata
LABEL org.opencontainers.image.title="Gash" \
      org.opencontainers.image.description="Evidence-first web security scanner" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.source="https://github.com/Xmar1881/Gash" \
      org.opencontainers.image.vendor="Xmar1881"

ENTRYPOINT ["/gash"]
CMD ["--help"]