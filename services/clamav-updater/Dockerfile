FROM golang:1.21-alpine AS builder
RUN apk add --no-cache git
WORKDIR /build
COPY main.go .
RUN go mod init clamav-updater && \
    go get github.com/gin-gonic/gin && \
    go build -o clamav-updater main.go

FROM alpine:latest
# Install docker-cli for runtime detection
# Note: Podman is not available in Alpine, but the service will detect it from the host if available
RUN apk add --no-cache ca-certificates docker-cli
WORKDIR /app
COPY --from=builder /build/clamav-updater .
EXPOSE 8082
CMD ["./clamav-updater"]

