FROM golang:1.25-alpine AS builder
RUN apk add --no-cache git gcc musl-dev yara-dev
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY main.go .
RUN CGO_ENABLED=1 go build -o yara-scanner main.go

FROM alpine:latest
# Install YARA runtime dependencies
RUN apk add --no-cache ca-certificates yara
WORKDIR /app
COPY --from=builder /build/yara-scanner .
# Rules are mounted as volume at runtime, not copied
# This ensures offline operation with local rule files only
EXPOSE 8081
CMD ["./yara-scanner"]
