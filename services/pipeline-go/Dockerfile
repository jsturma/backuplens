FROM golang:1.21-alpine AS builder
RUN apk add --no-cache git
WORKDIR /build
COPY main.go .
RUN go mod init pipeline && \
    go get github.com/gabriel-vasile/mimetype && \
    go get github.com/f-secure-foundry/go-clamd && \
    go get gopkg.in/yaml.v3 && \
    go build -o pipeline main.go

FROM alpine:latest
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /build/pipeline .
EXPOSE 8080
CMD ["./pipeline"]

