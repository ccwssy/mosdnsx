# MosdnsX 构建入口
#
# 版本号规则（见 README「版本号约定」）：
#   VERSION 文件写「基线-补丁集」，补丁集为整数编号，允许两级：mosdnsx<N> / mosdnsx<N>.<M>
#   发布构建（HEAD 正好在 tag 上）  → 版本就是该 tag
#   日常构建（无 tag）              → <VERSION>-<构建日期>-<短 SHA>
#
# 例：
#   VERSION = v5.3.4-mosdnsx1      日常 → v5.3.4-mosdnsx1-20261103-019e7e4
#   VERSION = v5.3.4-mosdnsx1.1    日常 → v5.3.4-mosdnsx1.1-20261104-a1b2c3d
#   tag     = v5.3.4-mosdnsx1.1    发布 → v5.3.4-mosdnsx1.1
#
# 用法：
#   make build          构建 ./mosdns
#   make test           跑单元测试
#   make docker         本地构建容器镜像
#   make version        打印将注入的版本号

VERSION_BASE := $(shell cat VERSION 2>/dev/null | tr -d '[:space:]')
GIT_TAG      := $(shell git describe --tags --exact-match 2>/dev/null)
BUILD_DATE   ?= $(shell date +%Y%m%d)
GIT_SHA      ?= $(shell git rev-parse --short=7 HEAD 2>/dev/null || echo nogit)
BUILD_VERSION := $(if $(GIT_TAG),$(GIT_TAG),$(VERSION_BASE)-$(BUILD_DATE)-$(GIT_SHA))

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
