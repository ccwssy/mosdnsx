FROM --platform=$BUILDPLATFORM golang:latest AS builder

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG CGO_ENABLED=0

COPY ./ /root/src/
WORKDIR /root/src/

# VERSION 由调用方注入完整版本号（Makefile / CI 已拼好日期与短 SHA）。
# 未传时回落到 git describe，避免出现 dev 之外的重复拼接。
ARG VERSION=""
RUN set -eux; \
    v="${VERSION:-$(git describe --tags --always 2>/dev/null || echo dev)}"; \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
        -ldflags "-s -w -X main.version=$v" -trimpath -o mosdns .

FROM alpine:latest

COPY --from=builder /root/src/mosdns /usr/bin/

RUN apk add --no-cache ca-certificates
