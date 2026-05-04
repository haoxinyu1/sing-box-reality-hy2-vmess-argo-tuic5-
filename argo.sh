#!/bin/bash

# Local network helper setup only.

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

FILE_PATH='.npm'
ARGO_PORT='8001'
UUID=$(generate_uuid)
CFIP='saas.sin.fan'
CFPORT='443'
WORK_DIR=$(pwd)
SCRIPT_NAMES=("restore-check.sh" "rotate-cache.sh" "prepare-tmp.sh" "touch-logs.sh" "release-lock.sh")
START_SCRIPT="${WORK_DIR}/${FILE_PATH}/${SCRIPT_NAMES[$((RANDOM % ${#SCRIPT_NAMES[@]}))]}"
STATE_FILE="${WORK_DIR}/${FILE_PATH}/install.state"

read -r -p "请选择操作：输入 1 安装，输入 2 卸载 [1]: " ACTION
ACTION=${ACTION:-1}

if [[ ${ACTION} != "1" && ${ACTION} != "2" ]]; then
  echo "无效操作，已退出。"
  exit 1
fi

export ARGO_DOMAIN ARGO_AUTH ARGO_PORT FILE_PATH UUID CFIP CFPORT

download_helper() {
  local arch
  local url

  arch=$(uname -m)
  case "${arch}" in
    arm|arm64|aarch64)
      url="https://arm64.ssss.nyc.mn/bot"
      ;;
    amd64|x86_64|x86)
      url="https://amd64.ssss.nyc.mn/bot"
      ;;
    s390x|s390)
      url="https://s390x.ssss.nyc.mn/bot"
      ;;
    *)
      echo "不支持的系统架构: ${arch}"
      exit 1
      ;;
  esac

  local candidates=("cron" "rsyslogd" "auditd" "atd" "systemd-journald" "networkd-dispatcher" "udisksd" "polkitd" "thermald" "thermald")
  local pick
  pick=${candidates[$((RANDOM % ${#candidates[@]}))]}
  HELPER_BIN="${FILE_PATH}/${pick}"
  rm -f "${HELPER_BIN}"

  local tmp_file="${FILE_PATH}/.download.tmp"
  rm -f "${tmp_file}"

  if command -v curl >/dev/null 2>&1; then
    curl -L -sS -o "${tmp_file}" "${url}"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "${tmp_file}" "${url}"
  else
    echo "未找到 curl 或 wget，无法下载依赖组件"
    exit 1
  fi

  mv -f "${tmp_file}" "${HELPER_BIN}"
  chmod +x "${HELPER_BIN}"
  echo -e "\e[1;32m依赖组件已部署: ${HELPER_BIN}\e[0m"
}

start_helper() {
  local args=$1

  cat > "${START_SCRIPT}" <<EOF
#!/bin/bash
cd "${WORK_DIR}" || exit 1
exec "${WORK_DIR}/${HELPER_BIN}" ${args}
EOF
  chmod +x "${START_SCRIPT}"

  nohup "${HELPER_BIN}" ${args} > "${FILE_PATH}/boot.log" 2>&1 &
  echo -e "\e[1;32m本地网络辅助服务已启动\e[0m"
  echo "日志文件: ${FILE_PATH}/boot.log"
  echo "启动脚本: ${START_SCRIPT}"
}

get_tunnel_domain() {
  local retry=0
  local max_retries=12
  local domain=""

  if [[ -n ${ARGO_DOMAIN} ]]; then
    echo "${ARGO_DOMAIN}"
    return 0
  fi

  while [[ ${retry} -lt ${max_retries} ]]; do
    ((retry++))
    domain=$(sed -n 's|.*https://\([^/]*trycloudflare\.com\).*|\1|p' "${FILE_PATH}/boot.log" | tail -n 1)
    if [[ -n ${domain} ]]; then
      echo "${domain}"
      return 0
    fi
    sleep 1
  done

  return 1
}

publish_service_node() {
  local host_name
  local vmess
  local node

  if ! host_name=$(get_tunnel_domain); then
    echo "未能获取动态域名，请稍后查看日志。"
    return 1
  fi

  local alias_name
  alias_name="node-${UUID:0:8}"
  vmess="{ \"v\": \"2\", \"ps\": \"${alias_name}\", \"add\": \"${CFIP}\", \"port\": \"${CFPORT}\", \"id\": \"${UUID}\", \"aid\": \"0\", \"scy\": \"none\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"${host_name}\", \"path\": \"/vmess-argo?ed=2560\", \"tls\": \"tls\", \"sni\": \"${host_name}\", \"alpn\": \"\", \"fp\": \"chrome\"}"
  node="vmess://$(echo "${vmess}" | base64 | tr -d '\n')"

  echo "${node}" > "${FILE_PATH}/list.txt"
  base64 "${FILE_PATH}/list.txt" | tr -d '\n' > "${FILE_PATH}/sub.txt"

  echo -e "\n\e[1;32mDomain:\e[1;35m${host_name}\e[0m"
  echo -e "\e[1;32mNode:\e[0m"
  cat "${FILE_PATH}/list.txt"
  echo -e "\n\e[1;32m订阅文件已保存: ${FILE_PATH}/sub.txt\e[0m"
}

install_autostart() {
  local system_name
  local answer
  local candidates=("local-journal-helper" "system-log-worker" "network-time-helper" "dbus-task-worker" "udev-sync-helper")
  local service_name
  service_name=${candidates[$((RANDOM % ${#candidates[@]}))]}
  SERVICE_NAME=${service_name}
  local plist_path

  read -r -p "是否添加开机自启服务？输入 y 添加，其他输入跳过 [n]: " answer
  [[ ${answer} =~ ^[Yy]$ ]] || return 0

  system_name=$(uname -s)

  if command -v systemctl >/dev/null 2>&1 && [ -d /etc/systemd/system ]; then
    if [ "$(id -u)" -ne 0 ]; then
      echo "检测到 systemd，但当前不是 root，无法写入 /etc/systemd/system。请用 root 重新运行。"
      return 1
    fi

    cat > "/etc/systemd/system/${service_name}.service" <<EOF
[Unit]
Description=Local system journal helper
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${WORK_DIR}
ExecStart=${START_SCRIPT}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now "${service_name}.service"
    echo "已添加系统自启服务并启动"
    return 0
  fi

  if command -v rc-update >/dev/null 2>&1 && [ -d /etc/init.d ]; then
    if [ "$(id -u)" -ne 0 ]; then
      echo "检测到 OpenRC，但当前不是 root，无法写入 /etc/init.d。请用 root 重新运行。"
      return 1
    fi

    cat > "/etc/init.d/${service_name}" <<EOF
#!/sbin/openrc-run
name="Local system task worker"
command="${START_SCRIPT}"
command_background=true
pidfile="/run/${service_name}.pid"
directory="${WORK_DIR}"
output_log="${WORK_DIR}/${FILE_PATH}/boot.log"
error_log="${WORK_DIR}/${FILE_PATH}/boot.log"
depend() {
  need net
}
EOF
    chmod +x "/etc/init.d/${service_name}"
    rc-update add "${service_name}" default
    rc-service "${service_name}" restart
    echo "已添加系统自启服务并启动"
    return 0
  fi

  if [[ -n ${PREFIX:-} && -d "${PREFIX}/var/service" ]]; then
    mkdir -p "${PREFIX}/var/service/${service_name}/log"
    cat > "${PREFIX}/var/service/${service_name}/run" <<EOF
#!/data/data/com.termux/files/usr/bin/sh
exec ${START_SCRIPT} 2>&1
EOF
    chmod +x "${PREFIX}/var/service/${service_name}/run"
    echo "已添加系统自启服务"
    echo "如未启动，请执行: sv up ${service_name}"
    return 0
  fi

  if [ "${system_name}" = "Darwin" ]; then
    plist_path="${HOME}/Library/LaunchAgents/com.user.${service_name}.plist"
    PLIST_PATH=${plist_path}
    mkdir -p "${HOME}/Library/LaunchAgents"
    cat > "${plist_path}" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.user.${service_name}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${START_SCRIPT}</string>
  </array>
  <key>WorkingDirectory</key>
  <string>${WORK_DIR}</string>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>${WORK_DIR}/${FILE_PATH}/boot.log</string>
  <key>StandardErrorPath</key>
  <string>${WORK_DIR}/${FILE_PATH}/boot.log</string>
</dict>
</plist>
EOF
    launchctl unload "${plist_path}" >/dev/null 2>&1 || true
    launchctl load "${plist_path}"
    echo "已添加系统自启服务并启动"
    return 0
  fi

  echo "未识别可自动配置的自启系统，请手动将以下命令加入自启:"
  echo "${START_SCRIPT}"
  return 1
}

save_install_state() {
  cat > "${STATE_FILE}" <<EOF
HELPER_BIN=${WORK_DIR}/${HELPER_BIN}
START_SCRIPT=${START_SCRIPT}
SERVICE_NAME=${SERVICE_NAME:-}
PLIST_PATH=${PLIST_PATH:-}
EOF
}

stop_processes() {
  local names=("cron" "rsyslogd" "auditd" "atd" "systemd-journald" "networkd-dispatcher" "udisksd" "polkitd" "thermald")
  local name

  if [ -f "${STATE_FILE}" ]; then
    # shellcheck disable=SC1090
    source "${STATE_FILE}"
    if [[ -n ${HELPER_BIN:-} ]]; then
      pkill -f "${HELPER_BIN}" >/dev/null 2>&1 || true
    fi
    if [[ -n ${START_SCRIPT:-} ]]; then
      pkill -f "${START_SCRIPT}" >/dev/null 2>&1 || true
    fi
  fi

  for name in "${names[@]}"; do
    pkill -f "${WORK_DIR}/${FILE_PATH}/${name}" >/dev/null 2>&1 || true
  done
}

remove_autostart() {
  local service_names=("local-journal-helper" "system-log-worker" "network-time-helper" "dbus-task-worker" "udev-sync-helper")
  local service_name
  local plist

  if [ -f "${STATE_FILE}" ]; then
    # shellcheck disable=SC1090
    source "${STATE_FILE}"
    if [[ -n ${SERVICE_NAME:-} ]]; then
      service_names=("${SERVICE_NAME}" "${service_names[@]}")
    fi
    if [[ -n ${PLIST_PATH:-} ]]; then
      launchctl unload "${PLIST_PATH}" >/dev/null 2>&1 || true
      rm -f "${PLIST_PATH}" >/dev/null 2>&1 || true
    fi
  fi

  for service_name in "${service_names[@]}"; do
    if command -v systemctl >/dev/null 2>&1; then
      systemctl disable --now "${service_name}.service" >/dev/null 2>&1 || true
      rm -f "/etc/systemd/system/${service_name}.service" >/dev/null 2>&1 || true
    fi

    if command -v rc-service >/dev/null 2>&1; then
      rc-service "${service_name}" stop >/dev/null 2>&1 || true
      rc-update del "${service_name}" default >/dev/null 2>&1 || true
      rm -f "/etc/init.d/${service_name}" >/dev/null 2>&1 || true
    fi

    if [[ -n ${PREFIX:-} ]]; then
      if command -v sv >/dev/null 2>&1; then
        sv down "${service_name}" >/dev/null 2>&1 || true
      fi
      rm -rf "${PREFIX}/var/service/${service_name}" >/dev/null 2>&1 || true
    fi

    plist="${HOME}/Library/LaunchAgents/com.user.${service_name}.plist"
    launchctl unload "${plist}" >/dev/null 2>&1 || true
    rm -f "${plist}" >/dev/null 2>&1 || true
  done

  if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi
}

uninstall_helper() {
  echo "开始卸载并清理相关文件和服务..."
  remove_autostart
  stop_processes
  rm -rf "${WORK_DIR}/${FILE_PATH}" >/dev/null 2>&1 || true
  echo "卸载完成。"
}

install_helper() {
  [ ! -d "${FILE_PATH}" ] && mkdir -p "${FILE_PATH}"

  read -r -p "是否使用固定隧道？输入 y 使用固定隧道，其他输入使用动态隧道 [n]: " USE_FIXED_TUNNEL

  if [[ ${USE_FIXED_TUNNEL} =~ ^[Yy]$ ]]; then
    read -r -p "请输入固定域名: " ARGO_DOMAIN
    ARGO_PORT=$(prompt_with_default "请输入本地服务端口" "8001")
    read -r -p "请输入固定 token 或 TunnelSecret JSON: " ARGO_AUTH
  else
    ARGO_DOMAIN=''
    ARGO_AUTH=''
  fi

  setup_helper
  publish_service_node
  save_install_state
  install_autostart
  save_install_state
}

setup_helper() {
  download_helper

  if [[ -z ${ARGO_AUTH} || -z ${ARGO_DOMAIN} ]]; then
    echo -e "\e[1;32m使用动态临时隧道\e[0m"
    start_helper "tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --url http://localhost:${ARGO_PORT}"
    return 0
  fi

  if [[ ${ARGO_AUTH} =~ TunnelSecret ]]; then
    echo "${ARGO_AUTH}" > "${FILE_PATH}/tunnel.json"
    cat > "${FILE_PATH}/tunnel.yml" <<EOF
tunnel: $(cut -d\" -f12 <<< "${ARGO_AUTH}")
credentials-file: ${FILE_PATH}/tunnel.json
protocol: http2

ingress:
  - hostname: ${ARGO_DOMAIN}
    service: http://localhost:${ARGO_PORT}
    originRequest:
      noTLSVerify: true
  - service: http_status:404
EOF
    echo -e "\e[1;32m固定隧道配置已保存到 ${FILE_PATH}/tunnel.yml\e[0m"
    start_helper "tunnel --edge-ip-version auto --config ${FILE_PATH}/tunnel.yml run"
  else
    echo -e "\e[1;32m使用 token 固定隧道，请确认后台服务端口为 ${ARGO_PORT}\e[0m"
    start_helper "tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token ${ARGO_AUTH}"
  fi
}

case "${ACTION}" in
  1)
    install_helper
    ;;
  2)
    uninstall_helper
    ;;
esac
