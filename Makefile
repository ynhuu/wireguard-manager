BINARY := wireguard-manager
BIN_DIR := bin
VERSION ?= dev
RELEASE_ZIPS = $(BINARY)-linux-amd64.zip $(BINARY)-linux-arm64.zip

.PHONY: all web build linux release clean test dev-backend dev-web

all: web build

## 构建前端到 internal/web/dist（go:embed 嵌入）
web:
	cd web && npm ci --no-fund --no-audit && npm run build

## 构建单二进制到 bin/（需先 make web）
build:
	mkdir -p $(BIN_DIR)
	go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o $(BIN_DIR)/$(BINARY) .

## 交叉编译 Linux 版本到 bin/
linux: web
	mkdir -p $(BIN_DIR)
	GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o $(BIN_DIR)/$(BINARY)-linux-amd64 .
	GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o $(BIN_DIR)/$(BINARY)-linux-arm64 .

release: linux
	@command -v zip >/dev/null 2>&1 || { echo '需要 zip 命令' >&2; exit 1; }
	@cd $(BIN_DIR) && zip -q -j $(BINARY)-linux-amd64.zip $(BINARY)-linux-amd64 && zip -q -j $(BINARY)-linux-arm64.zip $(BINARY)-linux-arm64
	@cd $(BIN_DIR) && if command -v shasum >/dev/null 2>&1; then shasum -a 256 $(RELEASE_ZIPS); \
	elif command -v sha256sum >/dev/null 2>&1; then sha256sum $(RELEASE_ZIPS); \
	else echo '需要 shasum 或 sha256sum' >&2; exit 1; fi > SHA256SUMS

test:
	go test ./internal/... -v

## 本地开发：后端 demo 模式 + vite 热更新（两个终端分别运行）
dev-backend:
	go run . --demo --listen 127.0.0.1:18080 --data-dir ./data

dev-web:
	cd web && npm run dev

clean:
	rm -rf $(BIN_DIR) data
	rm -rf internal/web/dist
