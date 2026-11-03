# mosdns 构建入口
#
# 版本号规则（见 README「版本号约定」）：
#   VERSION 文件写「基线-补丁集」，例如 v5.3.4-agh1
#   实际二进制版本 = <基线-补丁集>-<构建日期>-<短 SHA>
#   例：v5.3.4-agh1-20261103-be9fb22
#
# 用法：
#   make build          构建 ./mosdns
#   make test           跑单元测试
#   make docker         本地构建容器镜像
#   make version        打印将注入的版本号

VERSION_BASE := $(shell cat VERSION 2>/dev/null | tr -d '[:space:]')
BUILD_DATE   ?= $(shell date +%Y%m%d)
GIT_SHA      ?= $(shell git rev-parse --short=7 HEAD 2>/dev/null || echo nogit)
BUILD_VERSION := $(VERSION_BASE)-$(BUILD_DATE)-$(GIT_SHA)

LDFLAGS := -s -w -X main.version=$(BUILD_VERSION)
IMAGE   ?= ghcr.io/ccwssy/mosdnsx

.PHONY: all build test docker version clean

all: build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o mosdns .

test:
	go test ./plugin/executable/adguard/ ./coremain/

docker:
	docker build --build-arg VERSION=$(BUILD_VERSION) -t $(IMAGE):$(BUILD_VERSION) -t $(IMAGE):latest .

version:
	@echo $(BUILD_VERSION)

clean:
	rm -f mosdns
