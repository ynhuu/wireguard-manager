#!/bin/sh
# WireGuard Manager 自启动服务安装脚本
#
# 支持：
#   Debian / Ubuntu  → systemd
#   Alpine           → OpenRC（优先 supervise-daemon，回退 start-stop-daemon）
#
# 用法（需 root）：
#   sudo sh scripts/install-service.sh install [监听地址]   # 默认 127.0.0.1:8080
#   sudo sh scripts/install-service.sh uninstall
set -eu

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
# 二进制优先取脚本同目录，其次回退到项目 bin/ 目录
if [ -x "$SCRIPT_DIR/wireguard-manager" ]; then
    SRC_BIN="$SCRIPT_DIR/wireguard-manager"
else
    SRC_BIN="$SCRIPT_DIR/../bin/wireguard-manager"
fi
# WGM_ROOT：可选安装根前缀（容器/chroot/测试用），正常部署留空即可
PREFIX=${WGM_ROOT:-}
INSTALL_DIR="$PREFIX/opt/wgm"
INSTALL_BIN="$INSTALL_DIR/wireguard-manager"
DATA_DIR="$PREFIX/etc/wireguard-manager"
SVC_NAME=wireguard-manager
SYSTEMD_UNIT="$PREFIX/etc/systemd/system/$SVC_NAME.service"
OPENRC_INIT="$PREFIX/etc/init.d/$SVC_NAME"

log() { printf '[wgm] %s\n' "$*"; }
die() { printf '[wgm] 错误：%s\n' "$*" >&2; exit 1; }

require_root() {
    [ "$(id -u)" = "0" ] || die "请用 root 运行（sudo sh $0 ...）"
}

detect_init() {
    if [ -d "$PREFIX/run/systemd/system" ] && command -v systemctl >/dev/null 2>&1; then
        echo systemd
    elif command -v rc-service >/dev/null 2>&1; then
        echo openrc
    else
        echo unknown
    fi
}

install_binary() {
    [ -x "$SRC_BIN" ] || die "找不到二进制 $SRC_BIN，请先在项目根目录执行 make"
    mkdir -p "$INSTALL_DIR" "$DATA_DIR"
    chmod 700 "$DATA_DIR"
    cp "$SRC_BIN" "$INSTALL_BIN"
    chmod 755 "$INSTALL_BIN"
    log "已安装 $INSTALL_BIN"
}

write_systemd_unit() {
    mkdir -p "$(dirname "$SYSTEMD_UNIT")"
    cat > "$SYSTEMD_UNIT" <<EOF
[Unit]
Description=WireGuard Manager
Wants=network-online.target
After=network-online.target

[Service]
# 监听地址等全部由 $DATA_DIR/app.yaml 控制，修改后 systemctl restart 生效
ExecStart=$INSTALL_BIN
Restart=on-failure
RestartSec=3
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=true
ProtectSystem=strict
# 独立可写 /tmp：wg syncconf 的临时文件写在 /tmp（ProtectSystem=strict 下系统 /tmp 只读）
PrivateTmp=true
ReadWritePaths=/etc/wireguard $DATA_DIR

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable "$SVC_NAME"
    log "已注册 systemd 服务并设置开机自启"
}

write_openrc_service() {
    mkdir -p "$(dirname "$OPENRC_INIT")"
    # supervise-daemon 提供进程守护与自动拉起；旧版 OpenRC 回退 start-stop-daemon
    if command -v supervise-daemon >/dev/null 2>&1; then
        _bg="no"
        _pid=""
        _extra='supervisor="supervise-daemon"'
    else
        _bg="yes"
        _pid='pidfile="/run/${RC_SVCNAME}.pid"'
        _extra=''
    fi
    cat > "$OPENRC_INIT" <<EOF
#!/sbin/openrc-run
name="$SVC_NAME"
description="WireGuard management web console"
$_extra
command="$INSTALL_BIN"
command_args=""
command_background="$_bg"
$_pid
output_log="/var/log/$SVC_NAME.log"
error_log="/var/log/$SVC_NAME.err"

depend() {
    need net
    after firewall wg-quick
}
EOF
    chmod 755 "$OPENRC_INIT"
    rc-update add "$SVC_NAME" default
    log "已注册 OpenRC 服务并加入 default 运行级"
}

do_start() {
    case "$(detect_init)" in
        systemd) systemctl restart "$SVC_NAME" ;;
        openrc)  rc-service "$SVC_NAME" restart ;;
        *) die "未识别的 init 系统（仅支持 systemd / OpenRC）" ;;
    esac
}

do_install() {
    require_root
    INIT=$(detect_init)
    case "$INIT" in
        systemd|openrc) ;;
        *) die "未识别的 init 系统（仅支持 systemd / OpenRC）" ;;
    esac
    install_binary
    case "$INIT" in
        systemd) write_systemd_unit ;;
        openrc)  write_openrc_service ;;
    esac
    log "启动服务…"
    do_start
    log "完成。监听地址由 $DATA_DIR/app.yaml 的 listen 字段控制（默认 127.0.0.1:8080），"
    log "修改后执行 systemctl restart $SVC_NAME 或 rc-service $SVC_NAME restart 生效。"
}

do_uninstall() {
    require_root
    INIT=$(detect_init)
    case "$INIT" in
        systemd)
            systemctl disable --now "$SVC_NAME" 2>/dev/null || true
            rm -f "$SYSTEMD_UNIT"
            systemctl daemon-reload || true
            ;;
        openrc)
            rc-service "$SVC_NAME" stop 2>/dev/null || true
            rc-update del "$SVC_NAME" default 2>/dev/null || true
            rm -f "$OPENRC_INIT"
            ;;
        *) die "未识别的 init 系统" ;;
    esac
    rm -f "$INSTALL_BIN"
    rmdir "$INSTALL_DIR" 2>/dev/null || true
    log "已卸载服务（数据目录 $DATA_DIR 保留）"
}

case "${1:-}" in
    install)   do_install ;;
    uninstall) do_uninstall ;;
    *)
        cat >&2 <<EOF
用法: sudo sh $0 <命令>
  install     安装并启用开机自启（监听地址在 $DATA_DIR/app.yaml 的 listen 字段修改）
  uninstall   停止并移除服务（保留数据目录）
EOF
        exit 1
        ;;
esac
