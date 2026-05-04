#!/bin/bash

# 低资源节点服务端脚本：适合约 60M 硬盘、64M 内存的小机器。
# 只使用 sing-box，默认创建 vmess + websocket 入站，不依赖 Argo。

APP_DIR="${APP_DIR:-.node-server}"
BIN_PATH="${APP_DIR}/sing-box"
CONFIG_FILE="${APP_DIR}/config.json"
STATE_FILE="${APP_DIR}/state"
LOG_FILE="${APP_DIR}/node.log"
PID_FILE="${APP_DIR}/node.pid"
KEEPALIVE_SCRIPT="${APP_DIR}/keepalive.sh"
SERVICE_NAME="node-server"

DEFAULT_PORT="${DEFAULT_PORT:-8080}"
DEFAULT_WS_PATH="${DEFAULT_WS_PATH:-/ws}"

prompt_with_default() {
  local prompt=$1
  local default_value=$2
  local answer

  read -r -p "${prompt} [${default_value}]: " answer
  echo "${answer:-$default_value}"
}

generate_uuid() {
  if command -v uuidgen >/dev/null 2>&1; then
    uuidgen | tr 'A-Z' 'a-z'
  elif [ -r /proc/sys/kernel/random/uuid ]; then
    cat /proc/sys/kernel/random/uuid
  else
    printf '%08x-%04x-%04x-%04x-%012x\n' \
      "${RANDOM}${RANDOM}" \
      "${RANDOM}" \
      "$((RANDOM % 4096 + 16384))" \
      "$((RANDOM % 16384 + 32768))" \
      "${RANDOM}${RANDOM}${RANDOM}"
  fi
}

get_arch_base_url() {
  local arch
  arch=$(uname -m)

  case "${arch}" in
    amd64|x86_64|x86)
      echo "https://amd64.ssss.nyc.mn"
      ;;
    arm|arm64|aarch64)
      echo "https://arm64.ssss.nyc.mn"
      ;;
    s390x|s390)
      echo "https://s390x.ssss.nyc.mn"
      ;;
    *)
      echo "不支持的架构: ${arch}" >&2
      return 1
      ;;
  esac
}

download_sing_box() {
  local base_url
  base_url=$(get_arch_base_url) || exit 1

  mkdir -p "${APP_DIR}"
  rm -f "${BIN_PATH}"

  echo "正在下载 sing-box 到 ${BIN_PATH}"
  if command -v curl >/dev/null 2>&1; then
    curl -L -sS -o "${BIN_PATH}" "${base_url}/sb" || exit 1
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "${BIN_PATH}" "${base_url}/sb" || exit 1
  else
    echo "未找到 curl 或 wget，无法下载。"
    exit 1
  fi

  chmod +x "${BIN_PATH}"
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
      "tag": "vmess-ws-in",
      "type": "vmess",
      "listen": "::",
      "listen_port": ${NODE_PORT},
      "users": [
        {
          "uuid": "${UUID}"
        }
      ],
      "transport": {
        "type": "ws",
        "path": "${WS_PATH}",
        "early_data_header_name": "Sec-WebSocket-Protocol"
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

save_state() {
  cat > "${STATE_FILE}" <<EOF
UUID=${UUID}
NODE_PORT=${NODE_PORT}
WS_PATH=${WS_PATH}
SERVER_ADDR=${SERVER_ADDR}
EOF
}

load_state() {
  if [ -f "${STATE_FILE}" ]; then
    # shellcheck disable=SC1090
    source "${STATE_FILE}"
  fi
}

start_node() {
  mkdir -p "${APP_DIR}"
  nohup "$(pwd)/${BIN_PATH}" run -c "$(pwd)/${CONFIG_FILE}" > "${LOG_FILE}" 2>&1 &
  echo $! > "${PID_FILE}"
  sleep 1

  if kill -0 "$(cat "${PID_FILE}")" >/dev/null 2>&1; then
    echo "节点进程已启动，PID: $(cat "${PID_FILE}")"
  else
    echo "节点进程启动失败，请查看日志: ${LOG_FILE}"
    return 1
  fi
}

stop_node() {
  if [ -f "${PID_FILE}" ]; then
    kill "$(cat "${PID_FILE}")" >/dev/null 2>&1 || true
    rm -f "${PID_FILE}"
  fi

  pkill -f "$(pwd)/${BIN_PATH} run -c $(pwd)/${CONFIG_FILE}" >/dev/null 2>&1 || true
}

write_keepalive_script() {
  cat > "${KEEPALIVE_SCRIPT}" <<EOF
#!/bin/bash
cd "$(pwd)" || exit 1
if ! pgrep -f "$(pwd)/${BIN_PATH} run -c $(pwd)/${CONFIG_FILE}" >/dev/null 2>&1; then
  nohup "$(pwd)/${BIN_PATH}" run -c "$(pwd)/${CONFIG_FILE}" > "${LOG_FILE}" 2>&1 &
  echo \$! > "${PID_FILE}"
fi
EOF
  chmod +x "${KEEPALIVE_SCRIPT}"
}

install_systemd_service() {
  if ! command -v systemctl >/dev/null 2>&1 || [ ! -d /etc/systemd/system ]; then
    return 1
  fi

  if [ "$(id -u)" -ne 0 ]; then
    echo "检测到 systemd，但当前不是 root，跳过 systemd 自启。"
    return 1
  fi

  cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=Node Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$(pwd)
ExecStart=$(pwd)/${BIN_PATH} run -c $(pwd)/${CONFIG_FILE}
Restart=always
RestartSec=10
MemoryMax=56M

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now "${SERVICE_NAME}.service"
  echo "systemd 自启和保活已启用。"
  return 0
}

install_openrc_service() {
  if ! command -v rc-update >/dev/null 2>&1 || [ ! -d /etc/init.d ]; then
    return 1
  fi

  if [ "$(id -u)" -ne 0 ]; then
    echo "检测到 OpenRC，但当前不是 root，跳过 OpenRC 自启。"
    return 1
  fi

  cat > "/etc/init.d/${SERVICE_NAME}" <<EOF
#!/sbin/openrc-run
name="Node Server"
command="$(pwd)/${BIN_PATH}"
command_args="run -c $(pwd)/${CONFIG_FILE}"
command_background=true
pidfile="$(pwd)/${PID_FILE}"
directory="$(pwd)"
output_log="$(pwd)/${LOG_FILE}"
error_log="$(pwd)/${LOG_FILE}"
depend() {
  need net
}
EOF

  chmod +x "/etc/init.d/${SERVICE_NAME}"
  rc-update add "${SERVICE_NAME}" default
  rc-service "${SERVICE_NAME}" restart
  echo "OpenRC 自启和保活已启用。"
  return 0
}

install_cron_keepalive() {
  write_keepalive_script

  if ! command -v crontab >/dev/null 2>&1; then
    echo "未找到 crontab，仅完成当前启动。"
    return 1
  fi

  local marker="# ${SERVICE_NAME}-keepalive"
  local job="* * * * * $(pwd)/${KEEPALIVE_SCRIPT} ${marker}"
  local current
  current=$(crontab -l 2>/dev/null | grep -v "${marker}" || true)
  printf '%s\n%s\n' "${current}" "${job}" | crontab -
  echo "crontab 保活已启用：每分钟检查一次。"
}

install_autostart() {
  read -r -p "是否添加开机自启和保活？输入 y 添加，其他输入跳过 [y]: " answer
  answer=${answer:-y}
  [[ ${answer} =~ ^[Yy]$ ]] || return 0

  install_systemd_service && return 0
  install_openrc_service && return 0
  install_cron_keepalive
}

remove_autostart() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now "${SERVICE_NAME}.service" >/dev/null 2>&1 || true
    rm -f "/etc/systemd/system/${SERVICE_NAME}.service" >/dev/null 2>&1 || true
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi

  if command -v rc-service >/dev/null 2>&1; then
    rc-service "${SERVICE_NAME}" stop >/dev/null 2>&1 || true
    rc-update del "${SERVICE_NAME}" default >/dev/null 2>&1 || true
    rm -f "/etc/init.d/${SERVICE_NAME}" >/dev/null 2>&1 || true
  fi

  if command -v crontab >/dev/null 2>&1; then
    crontab -l 2>/dev/null | grep -v "# ${SERVICE_NAME}-keepalive" | crontab - >/dev/null 2>&1 || true
  fi
}

print_node() {
  local vmess
  local node
  local name

  name="node-${UUID:0:8}"
  vmess="{ \"v\": \"2\", \"ps\": \"${name}\", \"add\": \"${SERVER_ADDR}\", \"port\": \"${NODE_PORT}\", \"id\": \"${UUID}\", \"aid\": \"0\", \"scy\": \"none\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"\", \"path\": \"${WS_PATH}\", \"tls\": \"\", \"sni\": \"\", \"alpn\": \"\", \"fp\": \"chrome\"}"
  node="vmess://$(echo "${vmess}" | base64 | tr -d '\n')"

  echo
  echo "节点信息："
  echo "${node}"
  echo
  echo "服务端口: ${NODE_PORT}"
  echo "UUID: ${UUID}"
  echo "WS 路径: ${WS_PATH}"
  echo "配置目录: ${APP_DIR}"
}

install_flow() {
  mkdir -p "${APP_DIR}"

  UUID=$(generate_uuid)
  NODE_PORT=$(prompt_with_default "请输入节点端口" "${DEFAULT_PORT}")
  WS_PATH=$(prompt_with_default "请输入 WebSocket 路径" "${DEFAULT_WS_PATH}")
  SERVER_ADDR=$(prompt_with_default "请输入服务器 IP 或域名" "你的服务器IP")

  download_sing_box
  write_config
  save_state
  start_node
  install_autostart
  print_node
}

uninstall_flow() {
  echo "开始卸载..."
  remove_autostart
  stop_node
  rm -rf "${APP_DIR}" >/dev/null 2>&1 || true
  echo "卸载完成。"
}

status_flow() {
  load_state
  if pgrep -f "$(pwd)/${BIN_PATH} run -c $(pwd)/${CONFIG_FILE}" >/dev/null 2>&1; then
    echo "状态: 运行中"
  else
    echo "状态: 未运行"
  fi

  if [ -f "${STATE_FILE}" ]; then
    print_node
  fi
}

main() {
  echo "1) 安装"
  echo "2) 卸载"
  echo "3) 查看状态/节点"
  read -r -p "请选择操作 [1]: " action
  action=${action:-1}

  case "${action}" in
    1) install_flow ;;
    2) uninstall_flow ;;
    3) status_flow ;;
    *) echo "无效操作。"; exit 1 ;;
  esac
}

main
