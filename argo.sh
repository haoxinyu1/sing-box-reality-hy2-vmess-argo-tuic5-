#!/bin/bash

# Argo/Cloudflare Tunnel settings only.

prompt_with_default() {
  local prompt=$1
  local default_value=$2
  local answer

  read -r -p "${prompt} [${default_value}]: " answer
  echo "${answer:-$default_value}"
}

FILE_PATH='.npm'
ARGO_PORT='8001'
read -r -p "是否使用固定隧道？输入 y 使用固定隧道，其他输入使用动态隧道 [n]: " USE_FIXED_TUNNEL

if [[ ${USE_FIXED_TUNNEL} =~ ^[Yy]$ ]]; then
  read -r -p "请输入固定隧道域名: " ARGO_DOMAIN
  ARGO_PORT=$(prompt_with_default "请输入本地服务端口" "8001")
  read -r -p "请输入固定隧道 token 或 TunnelSecret JSON: " ARGO_AUTH
else
  ARGO_DOMAIN=''
  ARGO_AUTH=''
fi

export ARGO_DOMAIN ARGO_AUTH ARGO_PORT FILE_PATH

[ ! -d "${FILE_PATH}" ] && mkdir -p "${FILE_PATH}"
WORK_DIR=$(pwd)
START_SCRIPT="${WORK_DIR}/${FILE_PATH}/start_argo.sh"

download_cloudflared() {
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

  CLOUDFLARED="${FILE_PATH}/cloudflared"
  rm -f "${CLOUDFLARED}"

  if command -v curl >/dev/null 2>&1; then
    curl -L -sS -o "${CLOUDFLARED}" "${url}"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "${CLOUDFLARED}" "${url}"
  else
    echo "未找到 curl 或 wget，无法下载 cloudflared"
    exit 1
  fi

  chmod +x "${CLOUDFLARED}"
  echo -e "\e[1;32mcloudflared 已下载到 ${CLOUDFLARED}\e[0m"
}

run_cloudflared() {
  local args=$1

  cat > "${START_SCRIPT}" <<EOF
#!/bin/bash
cd "${WORK_DIR}" || exit 1
exec "${WORK_DIR}/${CLOUDFLARED}" ${args}
EOF
  chmod +x "${START_SCRIPT}"

  nohup "${CLOUDFLARED}" ${args} > "${FILE_PATH}/boot.log" 2>&1 &
  echo -e "\e[1;32mcloudflared 已后台启动\e[0m"
  echo "日志文件: ${FILE_PATH}/boot.log"
  echo "启动脚本: ${START_SCRIPT}"
}

install_autostart() {
  local system_name
  local answer
  local service_name="argo-cloudflared"
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
Description=Argo Cloudflared Tunnel
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
    echo "systemd 自启服务已安装并启动: ${service_name}.service"
    return 0
  fi

  if command -v rc-update >/dev/null 2>&1 && [ -d /etc/init.d ]; then
    if [ "$(id -u)" -ne 0 ]; then
      echo "检测到 OpenRC，但当前不是 root，无法写入 /etc/init.d。请用 root 重新运行。"
      return 1
    fi

    cat > "/etc/init.d/${service_name}" <<EOF
#!/sbin/openrc-run
name="Argo Cloudflared Tunnel"
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
    echo "OpenRC 自启服务已安装并启动: ${service_name}"
    return 0
  fi

  if [[ -n ${PREFIX:-} && -d "${PREFIX}/var/service" ]]; then
    mkdir -p "${PREFIX}/var/service/${service_name}/log"
    cat > "${PREFIX}/var/service/${service_name}/run" <<EOF
#!/data/data/com.termux/files/usr/bin/sh
exec ${START_SCRIPT} 2>&1
EOF
    chmod +x "${PREFIX}/var/service/${service_name}/run"
    echo "Termux 自启服务已创建: ${PREFIX}/var/service/${service_name}"
    echo "如未启动，请执行: sv up ${service_name}"
    return 0
  fi

  if [ "${system_name}" = "Darwin" ]; then
    plist_path="${HOME}/Library/LaunchAgents/com.user.${service_name}.plist"
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
    echo "launchd 自启服务已安装并启动: ${plist_path}"
    return 0
  fi

  echo "未识别可自动配置的自启系统，请手动将以下命令加入自启:"
  echo "${START_SCRIPT}"
  return 1
}

argo_configure() {
  download_cloudflared

  if [[ -z ${ARGO_AUTH} || -z ${ARGO_DOMAIN} ]]; then
    echo -e "\e[1;32m使用动态临时隧道\e[0m"
    run_cloudflared "tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --url http://localhost:${ARGO_PORT}"
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
    run_cloudflared "tunnel --edge-ip-version auto --config ${FILE_PATH}/tunnel.yml run"
  else
    echo -e "\e[1;32m使用 token 固定隧道，请确认 Cloudflare Tunnel 后台服务端口为 ${ARGO_PORT}\e[0m"
    run_cloudflared "tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token ${ARGO_AUTH}"
  fi
}

argo_configure
install_autostart
