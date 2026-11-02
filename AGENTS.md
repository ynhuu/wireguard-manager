# AGENTS.md

WireGuard 管理平台：Go 标准库后端 + React/Vite/Tailwind 前端，编译为单个二进制。

## 常用命令

```bash
make            # = make web && make build → bin/wireguard-manager
make linux      # 交叉编译 linux/amd64 + arm64 到 bin/
make test       # go test ./internal/... -v
make dev-backend  # 后端 --demo 模式 :18080（无需 root/wg）
make dev-web      # vite 热更新 :5173，/api 代理到 18080

go test ./internal/... -count=1   # 强制重跑全部测试
go build ./... && go vet ./...    # 提交前必须通过
gofmt -w <file>                   # Go 文件提交前格式化
cd web && npm run build           # 单独构建前端（输出到 internal/web/dist）
```

注意：`internal/web/dist/` 被 gitignore，裸 `go build` 前必须先构建前端（embed 需要）。

## 架构

```
main.go                    入口：flags(--listen/--data-dir/--demo)、auto-up、SPA 服务
internal/config/app.go     本程序 YAML 配置（app.yaml）+ 默认值
internal/config/wgconf.go  wg0.conf 解析器/渲染器/校验（纯 Go，含单测）
internal/store/            users.yaml(管理员+TOTP)、vault.yaml(AES-GCM 加密密钥库)、master.key
internal/auth/             TOTP、内存会话(CSRF token)、登录限速
internal/wg/               wg CLI 封装：Backend 接口 → Runner(真实) / DemoRunner(--demo)
                           dump 解析(接口行5列/peer行9列)、keygen(curve25519 纯Go)
internal/api/              net/http 路由(Go 1.22 method+wildcard pattern) + handlers + 审计日志
internal/web/embed.go      go:embed 前端产物
web/src/                   React 页面：Setup/Login/Dashboard/Peers/ConfigEditor/KeyVault/Settings
```

## 关键约定（违反会出过真实事故）

1. **所有 API 响应结构体必须带小写 json 标签**——漏标签会输出大写 Go 字段名，前端读 undefined 白屏（已发生过 3 次）。同理：**Go nil 切片序列化为 null 而非 []**，返回列表的字段必须初始化为空切片；前端对 API 数据一律 `?? []` 防御。
2. **[]byte 经 json.Marshal 是 base64 字符串不是数组**——二维码等二进制数据用完整 data URL 字符串传递。
3. **互斥锁纪律**：`vaultMu` 保护 vault.yaml 读-改-写，`cfgMu` 保护 app.yaml。拿到锁后第一行立即 `defer ...Unlock()`，禁止手动 Unlock 散落在分支里（曾导致死锁，回归测试见 internal/api/mutex_test.go）。
4. **文件写入三步**：校验 → 备份到固定名 `.bak`（覆盖式，只留一份）→ tmp 写入 + rename 原子替换。
5. **删除配置的联动**：运行中的接口先 wg-quick down，再删文件和全部 `.bak*`。
6. **私钥永不回显**：vault 私钥 AES-256-GCM 加密存储，仅通过客户端配置下载/二维码输出；GET 接口不返回任何密钥明文。私钥一经设置不可替换（PUT 仅允许原值为空时补录一次，冲突返回 409）；密钥字段入库前必须过 `config.ValidateKey`（base64/32 字节）。
7. **运行态不落盘**：内核 roaming 学到的对端 Endpoint 只在内存；任何功能不得把运行态写回 `.conf`（新建配置模板不含 `SaveConfig = true`，showconf/save 类接口已删除）。密钥库部署要求目标 conf 已存在——dump 里没有 Address/PostUp，禁止从运行态重建骨架文件。
8. **可选项语义**：PUT 更新中「省略字段 = 保持不变」用指针表达（如 `keyUpdateReq.Notes/Keepalive *type`）；嵌入 `keyCreateReq` 的 int 字段会被外层同名字段遮蔽，改默认行为时注意 json 解码取浅层。

## 后端模式

- 新增 API handler：在 `internal/api/server.go` 注册路由（写操作套 `s.auth()`，其内部含 CSRF 校验）；变更类操作调 `s.Audit(r, action, detail)` 记审计。
- 涉及 wg 命令的新能力：先扩展 `wg.Backend` 接口，Runner 实现真实命令，DemoRunner 同步实现假数据，否则 `--demo` 模式编译不过。
- dump 格式：接口行 `iface\tpriv\tpub\tport\tfwmark`(5列)，peer 行 8列(+前缀9列)；哨兵值 `(none)/(hidden)/off` 用 isNone() 判断。

## 前端模式

- fetch 统一走 `web/src/api.ts` 的 api.get/post/put/del，自动带 CSRF header；新增字段记得同步顶部 interface 定义。
- 401 全局处理：非 auth/setup/me 接口的 401 会清 CSRF 并 reload 回登录页，勿在这些路径上做特殊跳转。
- 弹窗统一用 `components/ui.tsx` 的 Modal（无滚动条设计，超高时遮罩层滚动）。
- 列表渲染 API 数据必须 `?? []`。

## 数据与部署

- 运行需 root 或 CAP_NET_ADMIN；数据目录默认 /etc/wireguard-manager（不可写回退 ./data）。
- `--demo` 模式模拟全部 wg 命令，macOS/无 root 环境开发用。
- systemd 示例、API 一览见 README.md。
