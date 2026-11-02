# WireGuard Manager

一个面向自建服务器的 WireGuard Web 管理平台。

后端使用 Go 标准库，前端使用 React + Vite + Tailwind，最终编译为单个二进制文件。它负责管理 WireGuard 接口、Peer、配置文件和加密密钥库，不重新实现 WireGuard 协议。

> 当前版本：`v1.0.0`

## 特性

- **实时状态**：接口、Peer、握手时间、流量和在线状态自动刷新
- **配置管理**：在线编辑、新建、删除 WireGuard 配置，保存前校验并自动备份
- **Peer 管理**：运行时移除 Peer，或通过密钥库部署到配置文件并立即应用
- **加密密钥库**：私钥使用 AES-256-GCM 加密保存，查询接口永不返回私钥明文
- **客户端配置**：下载客户端 `.conf` 或生成二维码导入
- **两步验证**：密码 + TOTP，带登录失败限速
- **审计日志**：记录登录、配置修改和密钥库等敏感操作
- **单二进制部署**：前端资源嵌入 Go 二进制，不需要 PHP 或 Node.js 运行时
- **Demo 模式**：无 Linux、root 或 WireGuard 环境也可以启动界面开发

## 安全边界

WireGuard 负责加密网络流量，WireGuard Manager 负责保护密钥、配置、权限和操作记录。

默认管理地址是 `127.0.0.1:8080`。不要把 NAS、数据库、文件服务、管理面板和 VPN 管理页面等私人服务端口直接暴露到公网。需要远程访问时，优先通过 WireGuard/VPN、内网、堡垒机或受控反向代理进入。

项目包含以下安全措施：

- HttpOnly + SameSite 会话 Cookie
- 写操作要求 CSRF Token
- 密码 bcrypt 存储，TOTP 按账号累计失败次数并限速
- 私钥 AES-256-GCM 加密，主密钥独立保存
- 配置写入采用校验、备份、临时文件和原子替换
- 运行态 Endpoint 不写回 `.conf`
- systemd 服务支持 `NoNewPrivileges`、`ProtectSystem`、`PrivateTmp` 和最小能力集

安全设计不代表免疫所有漏洞。宿主机、Linux、WireGuard 工具、NAS、反向代理和依赖库仍需持续更新。

## 快速开始

### 本地 Demo

需要 Node.js 18+ 和 Go 1.26.5+：

```bash
make
./bin/wireguard-manager --demo --listen 127.0.0.1:18080 --data-dir ./data
```

打开 <http://127.0.0.1:18080>，首次访问会进入管理员和 TOTP 初始化向导。

### Linux 生产部署

在 Linux 服务器上准备 WireGuard tools，然后构建：

```bash
make
sudo ./bin/wireguard-manager
```

程序默认读取 `/etc/wireguard-manager/app.yaml`，WireGuard 配置目录默认是 `/etc/wireguard`。运行真实 WireGuard 命令需要 root 或具有 `CAP_NET_ADMIN` / `CAP_NET_RAW` 的服务权限。

### GitHub Release 快捷安装

发布后可以直接下载经过 SHA-256 校验的二进制，并注册 systemd 或 OpenRC 服务：

```bash
curl -fsSL https://raw.githubusercontent.com/ynhuu/wireguard-manager/main/scripts/install.sh -o /tmp/wgm-install.sh
sudo sh /tmp/wgm-install.sh install
```

安装脚本：

- 支持 Linux `amd64` 和 `arm64`
- 默认监听 `127.0.0.1:8080`
- 安装到 `/opt/wgm/wireguard-manager`
- 数据目录为 `/etc/wireguard-manager`
- 不读取、不安装、不依赖 `Caddyfile`
- 卸载时保留数据目录

指定版本或仓库：

```bash
sudo sh /tmp/wgm-install.sh install --version v1.0.0
sudo sh /tmp/wgm-install.sh install --repo owner/repo --version v1.0.0
```

卸载程序和服务但保留数据：

```bash
sudo sh /tmp/wgm-install.sh uninstall
```

## 配置

配置文件：`/etc/wireguard-manager/app.yaml`

```yaml
listen: 127.0.0.1:8080
data_dir: /etc/wireguard-manager
wireguard:
  conf_dir: /etc/wireguard
  default_iface: wg0
  wg_bin: /usr/bin/wg
  wg_quick_bin: /usr/bin/wg-quick
  auto_up: true
  auto_up_skip: []
defaults:
  server_endpoint: ""
```

命令行参数：

| 参数 | 默认值 | 说明 |
|---|---|---|
| `--listen` | 配置文件值 | 覆盖监听地址，例如 `127.0.0.1:8080` |
| `--data-dir` | `/etc/wireguard-manager` | 数据目录 |
| `--demo` | 关闭 | 使用模拟 WireGuard 后端 |
| `--version` | - | 输出版本并退出 |

## 服务管理

手动安装已经构建的本地二进制：

```bash
sudo sh scripts/install-service.sh install
sudo systemctl status wireguard-manager
```

卸载服务但保留数据：

```bash
sudo sh scripts/install-service.sh uninstall
```

服务默认只监听本机。若需要远程访问，请先通过 VPN 或内网访问，或者自行配置 Caddy、Nginx 等 HTTPS 反向代理和 IP 白名单。反向代理是可选组件，安装脚本不会处理它。

## 开发与测试

```bash
make dev-backend &             # Demo 后端 :18080
make dev-web                   # Vite 开发服务器 :5173
go test ./internal/... -count=1
go build ./...
go vet ./...
```

前端单独构建：

```bash
cd web && npm run build
```

`internal/web/dist/` 被 Git 忽略。裸 `go build` 前请先执行 `make web` 或 `make`，否则 Go 的 `embed` 目录可能为空。

## 发布

构建 Linux 发布资产：

```bash
make release VERSION=v1.0.0
```

版本号通过 Go linker 参数注入，源码不保存发布版本。普通本地构建默认显示 `dev`。

输出文件：

```text
bin/wireguard-manager-linux-amd64.zip
bin/wireguard-manager-linux-arm64.zip
bin/SHA256SUMS
```

快捷安装脚本要求 GitHub Release 同时包含对应架构 ZIP 和 `SHA256SUMS`。ZIP 内的文件名必须是对应的裸二进制名称。

## 项目结构

```text
main.go                    程序入口、参数、SPA 服务和自动启动
internal/config/            app.yaml 与 wg 配置解析、校验、渲染
internal/store/             管理员、密钥库、主密钥和持久化
internal/auth/              TOTP、会话、CSRF 和登录限速
internal/wg/                wg CLI 封装、dump 解析、Demo 后端、密钥生成
internal/api/               HTTP 路由、API handler、审计日志
internal/web/               go:embed 前端构建产物
web/src/                    React 页面和组件
scripts/install.sh          GitHub Release 快捷安装
scripts/install-service.sh  本地二进制服务安装
```

## API 概览

```text
POST /api/setup                         初始化管理员和 TOTP
POST /api/auth/login | /api/auth/totp   两阶段登录
GET  /api/status                         WireGuard 实时状态
GET/PUT/DELETE /api/conf/*              配置文件管理
GET/POST/PUT/DELETE /api/keys[...]      密钥库管理
POST /api/keys/{id}/deploy              部署 Peer 到配置文件
POST /api/keys/{id}/unload              卸载 Peer 并应用
GET  /api/keys/{id}/client-config       下载客户端配置
GET  /api/keys/{id}/qrcode              获取客户端二维码
```

## 数据目录

```text
/etc/wireguard-manager/
├── app.yaml       程序配置
├── users.yaml     管理员 bcrypt 凭证和 TOTP
├── vault.yaml     AES-GCM 加密密钥库
├── master.key     密钥库主密钥，权限 0600
└── audit.log      JSONL 审计日志，自动轮转
```

备份密钥库时必须同时保护 `vault.yaml` 和 `master.key`。主密钥丢失时，密钥库中的私钥密文无法恢复。
