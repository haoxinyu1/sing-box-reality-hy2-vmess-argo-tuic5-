#!/bin/bash

# 低资源服务端脚本：适合约 60M 硬盘、64M 内存的小机器。

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
APP_DIR="${SCRIPT_DIR}/.sys-cache"
STATE_FILE="${APP_DIR}/.state"

# 候选伪装名池
_BIN_NAMES=("dbus-helper" "polkit-agent" "udev-worker" "acpid-handler" "rsync-daemon"
             "logrotate-ng" "atd-helper" "crond-svc" "avahi-daemon" "thermald-ng")
_SVC_NAMES=("dbus-system-helper" "polkit-system-agent" "udev-system-worker"
            "acpid-system-handler" "rsync-system-daemon" "logrotate-system-ng"
            "atd-system-helper" "crond-system-svc" "avahi-system-daemon" "thermald-system-ng")
_CFG_NAMES=("dbus.conf" "polkit.conf" "udev.conf" "acpid.conf" "rsync.conf"
            "logrotate.conf" "atd.conf" "crond.conf" "avahi.conf" "thermal.conf")
_LOG_NAMES=("dbus.log" "polkit.log" "udev.log" "acpid.log" "rsync.log"
            "logrotate.log" "atd.log" "crond.log" "avahi.log" "thermal.log")
_KA_NAMES=("dbus-watchdog.sh" "polkit-watchdog.sh" "udev-watchdog.sh" "acpid-watchdog.sh"
           "rsync-watchdog.sh" "logrotate-watchdog.sh" "atd-watchdog.sh"
           "crond-watchdog.sh" "avahi-watchdog.sh" "thermal-watchdog.sh")

pick_random() {
  local arr=("$@")
  echo "${arr[$((RANDOM % ${#arr[@]}))]}"
}

load_state() {
  [ -f "${STATE_FILE}" ] && source "${STATE_FILE}"
}

save_state() {
  mkdir -p "${APP_DIR}"
  cat > "${STATE_FILE}" <<EOF
BIN_NAME=${BIN_NAME}
SVC_NAME=${SVC_NAME}
CFG_NAME=${CFG_NAME}
LOG_NAME=${LOG_NAME}
KA_NAME=${KA_NAME}
UUID=${UUID}
NODE_PORT=${NODE_PORT}
WS_PATH=${WS_PATH}
SERVER_ADDR=${SERVER_ADDR}
TLS_DOMAIN=${TLS_DOMAIN}
COUNTRY_CODE=${COUNTRY_CODE}
EOF
  chmod 600 "${STATE_FILE}"
}

# 从 state 或随机生成伪装名，并导出所有路径变量
setup_paths() {
  BIN_PATH="${APP_DIR}/${BIN_NAME}"
  CONFIG_FILE="${APP_DIR}/${CFG_NAME}"
  CERT_FILE="${APP_DIR}/.tls.pem"
  KEY_FILE="${APP_DIR}/.tls.key"
  LOG_FILE="${APP_DIR}/${LOG_NAME}"
  PID_FILE="${APP_DIR}/.run.pid"
  KA_SCRIPT="${APP_DIR}/${KA_NAME}"
}

# ── 工具函数 ───────────────────────────────────────────────────────────────────

prompt_with_default() {
  local answer
  read -r -p "$1 [$2]: " answer
  echo "${answer:-$2}"
}

generate_uuid() {
  if command -v uuidgen >/dev/null 2>&1; then
    uuidgen | tr 'A-Z' 'a-z'
  elif [ -r /proc/sys/kernel/random/uuid ]; then
    cat /proc/sys/kernel/random/uuid
  else
    printf '%08x-%04x-%04x-%04x-%012x\n' \
      "$((RANDOM * RANDOM))" "${RANDOM}" \
      "$((RANDOM % 4096 + 16384))" \
      "$((RANDOM % 16384 + 32768))" \
      "$((RANDOM * RANDOM * RANDOM))"
  fi
}

generate_ws_path() {
  local seed
  seed=$(generate_uuid | tr -d '-')
  echo "/${seed:0:12}"
}

get_public_ip() {
  local ip
  if command -v curl >/dev/null 2>&1; then
    ip=$(curl -fsSL --max-time 6 https://api.ipify.org 2>/dev/null | tr -d '[:space:]')
    [ -z "${ip}" ] && ip=$(curl -fsSL --max-time 6 https://ipv4.ip.sb 2>/dev/null | tr -d '[:space:]')
  elif command -v wget >/dev/null 2>&1; then
    ip=$(wget -qO- --timeout=6 https://api.ipify.org 2>/dev/null | tr -d '[:space:]')
    [ -z "${ip}" ] && ip=$(wget -qO- --timeout=6 https://ipv4.ip.sb 2>/dev/null | tr -d '[:space:]')
  fi
  [ -n "${ip}" ] && echo "${ip}" || echo ""
}

get_country_code() {
  local code
  if command -v curl >/dev/null 2>&1; then
    code=$(curl -fsSL --max-time 6 https://ipinfo.io/country 2>/dev/null | tr -d '[:space:]')
    [ -z "${code}" ] && code=$(curl -fsSL --max-time 6 https://ipapi.co/country 2>/dev/null | tr -d '[:space:]')
  elif command -v wget >/dev/null 2>&1; then
    code=$(wget -qO- --timeout=6 https://ipinfo.io/country 2>/dev/null | tr -d '[:space:]')
    [ -z "${code}" ] && code=$(wget -qO- --timeout=6 https://ipapi.co/country 2>/dev/null | tr -d '[:space:]')
  fi
  if [[ ${code} =~ ^[A-Za-z]{2}$ ]]; then
    echo "${code}" | tr 'a-z' 'A-Z'
  else
    echo "XX"
  fi
}

get_arch_base_url() {
  case "$(uname -m)" in
    amd64|x86_64|x86) echo "https://amd64.ssss.nyc.mn" ;;
    arm|arm64|aarch64) echo "https://arm64.ssss.nyc.mn" ;;
    s390x|s390)        echo "https://s390x.ssss.nyc.mn" ;;
    *) echo "不支持的架构: $(uname -m)" >&2; return 1 ;;
  esac
}

# ── 核心操作 ───────────────────────────────────────────────────────────────────

download_bin() {
  local base_url
  base_url=$(get_arch_base_url) || exit 1
  mkdir -p "${APP_DIR}"
  rm -f "${BIN_PATH}"
  echo "正在下载核心组件..."
  if command -v curl >/dev/null 2>&1; then
    curl -L -sS -o "${BIN_PATH}" "${base_url}/sb" || { echo "下载失败"; exit 1; }
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "${BIN_PATH}" "${base_url}/sb" || { echo "下载失败"; exit 1; }
  else
    echo "未找到 curl 或 wget"; exit 1
  fi
  chmod +x "${BIN_PATH}"
}

write_tls_cert() {
  if command -v openssl >/dev/null 2>&1; then
    openssl ecparam -genkey -name prime256v1 -out "${KEY_FILE}" 2>/dev/null
    openssl req -new -x509 -days 3650 \
      -key "${KEY_FILE}" -out "${CERT_FILE}" \
      -subj "/CN=${TLS_DOMAIN}" 2>/dev/null
    return 0
  fi
  # 内置备用证书（无 openssl 时使用）
  cat > "${KEY_FILE}" <<'EOF'
-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIM4792SEtPqIt1ywqTd/0bYidBqpYV/++siNnfBYsdUYoAoGCCqGSM49
AwEHoUQDQgAE1kHafPj07rJG+HboH2ekAI4r+e6TL38GWASANnngZreoQDF16ARa
/TsyLyFoPkhLxSbehH/NBEjHtSZGaDhMqQ==
-----END EC PRIVATE KEY-----
EOF
  cat > "${CERT_FILE}" <<'EOF'
-----BEGIN CERTIFICATE-----
MIIBejCCASGgAwIBAgIUfWeQL3556PNJLp/veCFxGNj9crkwCgYIKoZIzj0EAwIw
EzERMA8GA1UEAwwIYmluZy5jb20wHhcNMjUwOTE4MTgyMDIyWhcNMzUwOTE2MTgy
MDIyWjATMREwDwYDVQQDDAhiaW5nLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEH
A0IABNZB2nz49O6yRvh26B9npACOK/nuky9/BlgEgDZ54Ga3qEAxdegEWv07Mi8h
aD5IS8Um3oR/zQRIx7UmRmg4TKmjUzBRMB0GA1UdDgQWBBTV1cFID7UISE7PLTBR
BfGbgkrMNzAfBgNVHSMEGDAWgBTV1cFID7UISE7PLTBRBfGbgkrMNzAPBgNVHRMB
Af8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIAIDAJvg0vd/ytrQVvEcSm6XTlB+
eQ6OFb9LbLYL9f+sAiAffoMbi4y/0YUSlTtz7as9S8/lciBF5VCUoVIKS+vX2g==
-----END CERTIFICATE-----
EOF
}

write_config() {
  cat > "${CONFIG_FILE}" <<EOF
{
  "log": {
    "disabled": true,
    "level": "error",
    "timestamp": false
  },
  "inbounds": [
    {
      "tag": "in",
      "type": "vless",
      "listen": "::",
      "listen_port": ${NODE_PORT},
      "users": [
        {
          "uuid": "${UUID}",
          "flow": ""
        }
      ],
      "transport": {
        "type": "ws",
        "path": "${WS_PATH}",
        "early_data_header_name": "Sec-WebSocket-Protocol"
      },
      "tls": {
        "enabled": true,
        "server_name": "${TLS_DOMAIN}",
        "certificate_path": "${CERT_FILE}",
        "key_path": "${KEY_FILE}"
      }
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ]
}
EOF
}

stop_proc() {
  [ -f "${PID_FILE}" ] && kill "$(cat "${PID_FILE}")" 2>/dev/null; rm -f "${PID_FILE}"
  pkill -f "${BIN_PATH} run -c ${CONFIG_FILE}" 2>/dev/null || true
  sleep 1
}

start_proc() {
  nohup "${BIN_PATH}" run -c "${CONFIG_FILE}" > "${LOG_FILE}" 2>&1 &
  echo $! > "${PID_FILE}"
  sleep 1
  if kill -0 "$(cat "${PID_FILE}")" 2>/dev/null; then
    echo "服务已启动"
    return 0
  else
    echo "服务启动失败，请查看日志: ${LOG_FILE}"
    return 1
  fi
}

write_ka_script() {
  cat > "${KA_SCRIPT}" <<EOF
#!/bin/bash
if ! pgrep -f "${BIN_PATH} run -c ${CONFIG_FILE}" >/dev/null 2>&1; then
  nohup "${BIN_PATH}" run -c "${CONFIG_FILE}" >> "${LOG_FILE}" 2>&1 &
  echo \$! > "${PID_FILE}"
fi
EOF
  chmod +x "${KA_SCRIPT}"
}

# ── 自启安装 ──────────────────────────────────────────────────────────────────

install_systemd() {
  command -v systemctl >/dev/null 2>&1 && [ -d /etc/systemd/system ] || return 1
  [ "$(id -u)" -eq 0 ] || { echo "需要 root 才能配置 systemd"; return 1; }

  cat > "/etc/systemd/system/${SVC_NAME}.service" <<EOF
[Unit]
Description=System cache optimization helper
After=network.target

[Service]
Type=simple
WorkingDirectory=${APP_DIR}
ExecStart=${BIN_PATH} run -c ${CONFIG_FILE}
Restart=always
RestartSec=10
MemoryMax=56M
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now "${SVC_NAME}.service" >/dev/null 2>&1
  echo "开机自启已配置 (systemd)"
  return 0
}

install_openrc() {
  command -v rc-update >/dev/null 2>&1 && [ -d /etc/init.d ] || return 1
  [ "$(id -u)" -eq 0 ] || { echo "需要 root 才能配置 OpenRC"; return 1; }

  cat > "/etc/init.d/${SVC_NAME}" <<EOF
#!/sbin/openrc-run
description="System cache optimization helper"
command="${BIN_PATH}"
command_args="run -c ${CONFIG_FILE}"
command_background=true
pidfile="${PID_FILE}"
directory="${APP_DIR}"
output_log="${LOG_FILE}"
error_log="${LOG_FILE}"
depend() { need net; }
EOF
  chmod +x "/etc/init.d/${SVC_NAME}"
  rc-update add "${SVC_NAME}" default >/dev/null 2>&1
  rc-service "${SVC_NAME}" start >/dev/null 2>&1
  echo "开机自启已配置 (OpenRC)"
  return 0
}

install_cron() {
  write_ka_script
  command -v crontab >/dev/null 2>&1 || { echo "未找到 crontab，跳过保活配置"; return 1; }
  local marker="## ${SVC_NAME}"
  local current
  current=$(crontab -l 2>/dev/null | grep -v "${marker}" || true)
  printf '%s\n%s\n' "${current}" "* * * * * ${KA_SCRIPT} ${marker}" | crontab -
  echo "保活已配置 (crontab)"
}

install_autostart() {
  stop_proc
  install_systemd && return 0
  install_openrc  && return 0
  start_proc
  install_cron
}

# ── 卸载清理 ──────────────────────────────────────────────────────────────────

remove_autostart() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now "${SVC_NAME}.service" 2>/dev/null || true
    rm -f "/etc/systemd/system/${SVC_NAME}.service"
    systemctl daemon-reload 2>/dev/null || true
  fi
  if command -v rc-service >/dev/null 2>&1; then
    rc-service "${SVC_NAME}" stop 2>/dev/null || true
    rc-update del "${SVC_NAME}" default 2>/dev/null || true
    rm -f "/etc/init.d/${SVC_NAME}"
  fi
  if command -v crontab >/dev/null 2>&1; then
    crontab -l 2>/dev/null | grep -v "## ${SVC_NAME}" | crontab - 2>/dev/null || true
  fi
}

# ── 节点输出 ──────────────────────────────────────────────────────────────────

print_node() {
  local name encoded_path node
  name="${COUNTRY_CODE:-XX}-${UUID:0:8}"
  encoded_path=$(printf '%s' "${WS_PATH}" | sed 's|/|%2F|g')
  node="vless://${UUID}@${SERVER_ADDR}:${NODE_PORT}?encryption=none&security=tls&sni=${TLS_DOMAIN}&type=ws&host=${TLS_DOMAIN}&path=${encoded_path}&fp=chrome&allowInsecure=1#${name}"
  echo
  echo "=============================="
  echo "节点 (VLESS+WS+TLS):"
  echo "${node}"
  echo "=============================="
  echo "地址: ${SERVER_ADDR}:${NODE_PORT}"
  echo "UUID: ${UUID}"
  echo "路径: ${WS_PATH}"
  echo "TLS : 自签证书，客户端需开启 allowInsecure"
  echo
}

# ── 主流程 ────────────────────────────────────────────────────────────────────

install_flow() {
  # 随机选取伪装名
  BIN_NAME=$(pick_random "${_BIN_NAMES[@]}")
  SVC_NAME=$(pick_random "${_SVC_NAMES[@]}")
  CFG_NAME=$(pick_random "${_CFG_NAMES[@]}")
  LOG_NAME=$(pick_random "${_LOG_NAMES[@]}")
  KA_NAME=$(pick_random  "${_KA_NAMES[@]}")
  setup_paths

  # 生成节点参数
  UUID=$(generate_uuid)
  NODE_PORT=$(prompt_with_default "请输入节点端口" "8080")
  WS_PATH=$(generate_ws_path)

  echo "正在获取服务器信息..."
  SERVER_ADDR=$(get_public_ip)
  COUNTRY_CODE=$(get_country_code)
  TLS_DOMAIN=${SERVER_ADDR}

  if [ -z "${SERVER_ADDR}" ]; then
    echo "无法获取公网 IP，请检查网络"
    exit 1
  fi

  echo "服务器: ${SERVER_ADDR} [${COUNTRY_CODE}]"

  mkdir -p "${APP_DIR}"
  chmod 700 "${APP_DIR}"

  download_bin
  write_tls_cert
  write_config
  save_state
  install_autostart
  print_node
}

uninstall_flow() {
  load_state
  setup_paths

  echo "正在停止服务并清理..."
  remove_autostart
  stop_proc
  rm -rf "${APP_DIR}"
  echo "卸载完成"
}

status_flow() {
  load_state
  setup_paths

  if pgrep -f "${BIN_PATH} run -c ${CONFIG_FILE}" >/dev/null 2>&1; then
    echo "状态: 运行中"
  else
    echo "状态: 未运行"
  fi
  [ -f "${STATE_FILE}" ] && print_node
}

main() {
  echo "1) 安装"
  echo "2) 卸载"
  echo "3) 查看状态/节点"
  read -r -p "请选择操作 [1]: " action
  case "${action:-1}" in
    1) install_flow ;;
    2) uninstall_flow ;;
    3) status_flow ;;
    *) echo "无效操作"; exit 1 ;;
  esac
}

main
