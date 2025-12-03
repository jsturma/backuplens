FROM golang:1.25-alpine AS builder
RUN apk add --no-cache git
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY main.go .
RUN go build -o clamav-updater main.go

FROM alpine:latest
# Install docker-cli for runtime detection
# Note: Podman is not available in Alpine, but the service will detect it from the host if available
RUN apk add --no-cache ca-certificates docker-cli
WORKDIR /app
COPY --from=builder /build/clamav-updater .
EXPOSE 8082
CMD ["./clamav-updater"]

