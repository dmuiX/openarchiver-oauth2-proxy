# Build Stage
FROM golang:1.23-alpine AS builder

WORKDIR /app
COPY . .

# Download dependencies
RUN go mod download

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -o openarchiver-oauth2-proxy ./cmd/server

# Runtime Stage
FROM alpine:latest

WORKDIR /app
RUN apk add --no-cache ca-certificates bash

COPY --from=builder /app/openarchiver-oauth2-proxy .
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
