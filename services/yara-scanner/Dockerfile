FROM golang:1.21-alpine AS builder
RUN apk add --no-cache git
WORKDIR /build
COPY main.go .
RUN go mod init yara-scanner && \
    go get github.com/gin-gonic/gin && \
    go get github.com/hillu/go-yara/v4 && \
    go build -o yara-scanner main.go

FROM alpine:latest
# Install YARA runtime dependencies
RUN apk add --no-cache ca-certificates yara
WORKDIR /app
COPY --from=builder /build/yara-scanner .
# Rules are mounted as volume at runtime, not copied
# This ensures offline operation with local rule files only
EXPOSE 8081
CMD ["./yara-scanner"]
