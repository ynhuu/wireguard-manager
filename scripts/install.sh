#!/bin/sh
# WireGuard Manager 快捷安装脚本
#
# 用法：
#   sudo sh scripts/install.sh install [--version v1.0.0] [--repo owner/repo]
#   sudo sh scripts/install.sh uninstall [--yes]
#
# 安装内容：
#   /opt/wgm/wireguard-manager              程序
#   /etc/wireguard-manager                  数据目录（保留管理员、密钥库和审计日志）
#   systemd / OpenRC                         自启动服务
#
# Release 资产约定：
#   wireguard-manager-linux-amd64.zip 或 wireguard-manager-linux-arm64.zip
#   SHA256SUMS
set -eu
umask 077

REPO_DEFAULT=${WGM_REPO:-ynhuu/wireguard-manager}
INSTALL_DIR=/opt/wgm
INSTALL_BIN=$INSTALL_DIR/wireguard-manager
DATA_DIR=/etc/wireguard-manager
SERVICE=wireguard-manager
SYSTEMD_UNIT=/etc/systemd/system/$SERVICE.service
OPENRC_INIT=/etc/init.d/$SERVICE

log() { printf '[wgm] %s\n' "$*"; }
die() { printf '[wgm] 错误：%s\n' "$*" >&2; exit 1; }

usage() {
    cat <<'EOF'
用法：
  sudo sh scripts/install.sh install [--version v1.0.0] [--repo owner/repo]
  sudo sh scripts/install.sh uninstall [--yes]
  sh scripts/install.sh --help

默认从 ynhuu/wireguard-manager 的 latest Release 下载 Linux 二进制。
安装默认监听 127.0.0.1:8080，远程访问建议先连接 VPN 或配置 HTTPS 反向代理。
安装脚本不读取、不安装 Caddy 或 Caddyfile；HTTPS 反向代理按需单独配置。
版本参数使用完整 Git tag，例如 v1.0.0。
EOF
}

action=${1:---help}
case "$action" in
    --help|-h) usage; exit 0 ;;
    install|uninstall) shift ;;
    *) usage; exit 1 ;;
esac

repo=$REPO_DEFAULT
version=
yes=no
while [ "$#" -gt 0 ]; do
    case "$1" in
        --repo)
            [ "$#" -ge 2 ] || die '--repo 缺少参数'
            repo=$2
            shift 2
            ;;
        --version)
            [ "$#" -ge 2 ] || die '--version 缺少参数'
            version=$2
            shift 2
            ;;
        --yes)
            yes=yes
            shift
            ;;
        *) die "未知参数：$1" ;;
    esac
done

require_root() {
    [ "$(id -u)" = 0 ] || die "请用 root 运行：sudo sh $0 $action"
}

detect_init() {
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        printf '%s\n' systemd
    elif command -v rc-service >/dev/null 2>&1 && [ -d /run/openrc ]; then
        printf '%s\n' openrc
    else
        die '未识别的 init 系统，仅支持正在运行的 systemd 或 OpenRC'
    fi
}

validate_args() {
    printf '%s\n' "$repo" | grep -Eq '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$' \
        || die '仓库格式应为 owner/repo'
    if [ -n "$version" ]; then
        printf '%s\n' "$version" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9_.-]*$' \
            || die '版本 tag 含不支持的字符'
    fi
}

tmp=
cleanup() {
    if [ -n "$tmp" ]; then
        rm -rf "$tmp"
    fi
}
trap cleanup EXIT HUP INT TERM

fetch() {
    curl --fail --location --silent --show-error \
        --proto '=https' --proto-redir '=https' \
        --connect-timeout 15 --max-time 300 "$1" -o "$2"
}

download_binary() {
    case "$(uname -m)" in
        x86_64|amd64) arch=amd64 ;;
        aarch64|arm64) arch=arm64 ;;
        *) die "不支持的 CPU 架构：$(uname -m)，当前 Release 提供 amd64 和 arm64" ;;
    esac
    asset="wireguard-manager-linux-$arch.zip"
    binary_entry="wireguard-manager-linux-$arch"
    if [ -n "$version" ]; then
        base_url="https://github.com/$repo/releases/download/$version"
    else
        base_url="https://github.com/$repo/releases/latest/download"
    fi

    tmp=$(mktemp -d "${TMPDIR:-/tmp}/wgm-install.XXXXXXXX")
    log "下载 $repo 的 $asset 与 SHA256SUMS…"
    fetch "$base_url/$asset" "$tmp/archive.zip"
    fetch "$base_url/SHA256SUMS" "$tmp/SHA256SUMS"

    expected=$(awk -v name="$asset" '$2 == name || $2 == "*" name { print $1 }' "$tmp/SHA256SUMS")
    count=$(printf '%s\n' "$expected" | awk 'NF { n++ } END { print n + 0 }')
    [ "$count" = 1 ] || die "SHA256SUMS 中找不到 $asset 或存在重复记录"
    case "$expected" in
        *[!0-9a-fA-F]*) die 'SHA-256 格式错误' ;;
    esac

    if command -v sha256sum >/dev/null 2>&1; then
        actual=$(sha256sum "$tmp/archive.zip" | awk '{ print $1 }')
    elif command -v shasum >/dev/null 2>&1; then
        actual=$(shasum -a 256 "$tmp/archive.zip" | awk '{ print $1 }')
    else
        die '需要 sha256sum 或 shasum 来校验下载文件'
    fi
    [ "$(printf '%s' "$expected" | tr 'A-F' 'a-f')" = "$actual" ] \
        || die 'SHA-256 校验失败，拒绝安装'
    unzip -p "$tmp/archive.zip" "$binary_entry" > "$tmp/binary" \
        || die "ZIP 中缺少目标二进制 $binary_entry"
    [ -s "$tmp/binary" ] || die '下载的二进制为空'
}

write_systemd_unit() {
    mkdir -p /etc/systemd/system
    cat > "$SYSTEMD_UNIT" <<EOF
[Unit]
Description=WireGuard Manager
Wants=network-online.target
After=network-online.target

[Service]
ExecStart=$INSTALL_BIN
WorkingDirectory=$INSTALL_DIR
Restart=on-failure
RestartSec=3
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
UMask=0077
ReadWritePaths=/etc/wireguard $DATA_DIR

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable "$SERVICE"
}

write_openrc_service() {
    mkdir -p /etc/init.d
    if command -v supervise-daemon >/dev/null 2>&1; then
        supervisor_line='supervisor="supervise-daemon"'
        background_line='command_background="no"'
        pid_line=
    else
        supervisor_line=
        background_line='command_background="yes"'
        pid_line='pidfile="/run/${RC_SVCNAME}.pid"'
    fi
    cat > "$OPENRC_INIT" <<EOF
#!/sbin/openrc-run
name="$SERVICE"
description="WireGuard management web console"
$supervisor_line
command="$INSTALL_BIN"
$background_line
$pid_line
output_log="/var/log/$SERVICE.log"
error_log="/var/log/$SERVICE.err"

depend() {
    need net
    after firewall wg-quick
}
EOF
    chmod 755 "$OPENRC_INIT"
    rc-update add "$SERVICE" default
}

start_service() {
    case "$1" in
        systemd) systemctl restart "$SERVICE" ;;
        openrc) rc-service "$SERVICE" restart ;;
    esac
}

confirm_uninstall() {
    [ "$yes" = yes ] && return 0
    [ -r /dev/tty ] && [ -w /dev/tty ] || die '卸载需要 --yes 或交互终端确认'
    printf '[wgm] 将停止并移除程序及服务，保留数据目录 %s。继续？ [y/N]：' "$DATA_DIR" > /dev/tty
    IFS= read -r answer < /dev/tty || die '输入已取消'
    case "$answer" in y|Y) ;; *) die '已取消' ;; esac
}

do_install() {
    require_root
    validate_args
    command -v curl >/dev/null 2>&1 || die '请先安装 curl 和 CA 证书'
    command -v unzip >/dev/null 2>&1 || die '请先安装 unzip'
    command -v install >/dev/null 2>&1 || die '系统缺少 install 命令'
    init=$(detect_init)
    download_binary

    mkdir -p "$INSTALL_DIR" "$DATA_DIR"
    chmod 700 "$DATA_DIR"
    install -m 755 "$tmp/binary" "$INSTALL_BIN"
    case "$init" in
        systemd) write_systemd_unit ;;
        openrc) write_openrc_service ;;
    esac
    start_service "$init"

    log "安装完成：$INSTALL_BIN"
    log "数据目录保留为：$DATA_DIR"
    log '默认监听 127.0.0.1:8080；请通过 SSH/VPN 或 HTTPS 反向代理访问。'
    log "首次访问会进入初始化向导；服务状态可用 $SERVICE 的系统服务命令查看。"
}

do_uninstall() {
    require_root
    confirm_uninstall
    init=$(detect_init)
    case "$init" in
        systemd)
            systemctl disable --now "$SERVICE" 2>/dev/null || true
            rm -f "$SYSTEMD_UNIT"
            systemctl daemon-reload || true
            ;;
        openrc)
            rc-service "$SERVICE" stop 2>/dev/null || true
            rc-update del "$SERVICE" default 2>/dev/null || true
            rm -f "$OPENRC_INIT"
            ;;
    esac
    rm -f "$INSTALL_BIN"
    rmdir "$INSTALL_DIR" 2>/dev/null || true
    log "已卸载程序和服务；数据目录 $DATA_DIR 保留。"
}

case "$action" in
    install) do_install ;;
    uninstall) do_uninstall ;;
esac
