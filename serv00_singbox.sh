#!/bin/bash

re="\033[0m"
red="\033[1;91m"
green="\e[1;32m"
yellow="\e[1;33m"
purple="\e[1;35m"
red() { echo -e "\e[1;91m$1\033[0m"; }
green() { echo -e "\e[1;32m$1\033[0m"; }
yellow() { echo -e "\e[1;33m$1\033[0m"; }
purple() { echo -e "\e[1;35m$1\033[0m"; }
reading() { read -p "$(red "$1")" "$2"; }

# 获取当前用户名
USERNAME=$(whoami)
# 获取当前主机名
HOSTNAME=$(hostname)
# 停止程序线程
ps aux | grep $(whoami) | grep -v "sshd\|bash\|grep" | awk '{print $2}' | xargs -r kill -9 2>/dev/null

# 设置工作目录和文件路径
if [[ "$HOSTNAME" == "s1.ct8.pl" ]]; then
    WORKDIR="/home/$USERNAME/domains/${USERNAME}.ct8.pl/singbox"
    FILE_PATH="/home/$USERNAME/domains/${USERNAME}.ct8.pl/socks5"
else
    WORKDIR="/home/$USERNAME/domains/${USERNAME}.serv00.net/singbox"
    FILE_PATH="/home/$USERNAME/domains/${USERNAME}.serv00.net/socks5"
fi

# 删除并重新创建工作目录
if [ -d "$WORKDIR" ]; then
    echo "Deleting existing WORKDIR: $WORKDIR"
    rm -rfv "$WORKDIR"
    if [ $? -ne 0 ]; then
        echo "Error: Failed to delete WORKDIR: $WORKDIR"
        exit 1
    fi
fi
mkdir -p "$WORKDIR" && chmod 777 "$WORKDIR"
if [ $? -ne 0 ]; then
    echo "Error: Failed to create WORKDIR: $WORKDIR"
    exit 1
fi
echo "Successfully created WORKDIR: $WORKDIR"

# 删除并重新创建文件路径
if [ -d "$FILE_PATH" ]; then
    echo "Deleting existing FILE_PATH: $FILE_PATH"
    rm -rfv "$FILE_PATH"
    if [ $? -ne 0 ]; then
        echo "Error: Failed to delete FILE_PATH: $FILE_PATH"
        exit 1
    fi
fi
mkdir -p "$FILE_PATH" && chmod 777 "$FILE_PATH"
if [ $? -ne 0 ]; then
    echo "Error: Failed to create FILE_PATH: $FILE_PATH"
    exit 1
fi
echo "Successfully created FILE_PATH: $FILE_PATH"


read_vmess_port() {
    while true; do
        reading "请输入vmess端口 (面板开放的tcp端口): " vmess_port
        if [[ "$vmess_port" =~ ^[0-9]+$ ]] && [ "$vmess_port" -ge 1 ] && [ "$vmess_port" -le 65535 ]; then
            green "你的vmess端口为: $vmess_port"
            break
        else
            yellow "输入错误，请重新输入面板开放的TCP端口"
        fi
    done
}

read_hy2_port() {
    while true; do
        reading "请输入hysteria2端口 (面板开放的UDP端口): " hy2_port
        if [[ "$hy2_port" =~ ^[0-9]+$ ]] && [ "$hy2_port" -ge 1 ] && [ "$hy2_port" -le 65535 ]; then
            green "你的hysteria2端口为: $hy2_port"
            break
        else
            yellow "输入错误，请重新输入面板开放的UDP端口"
        fi
    done
}

read_socks_variables() {
    while true; do
        reading "请输入socks端口 (面板开放的TCP端口): " socks_port
        if [[ ! -z "$socks_port" ]]; then
            green "你的socks端口为: $socks_port"
            break
        else
            yellow "输入错误，请重新输入面板开放的TCP端口"
        fi
    done

    while true; do
        reading "请输入socks用户名: " socks_user
        if [[ ! -z "$socks_user" ]]; then
            green "你的socks用户名为: $socks_user"
            break
        else
            yellow "用户名不能为空，请重新输入"
        fi
    done

    while true; do
        reading "请输入socks密码，不能包含:和@符号: " socks_pass
        if [[ ! -z "$socks_pass" ]]; then
            green "你的socks密码为: $socks_pass"
            break
        else
            yellow "密码不能为空，请重新输入"
        fi
    done
}



# UUID 生成函数
generate_uuid() {
    for i in {1..3}; do
        uuid=$(uuidgen)
        if [[ -n "$uuid" ]]; then
            echo "$uuid"
            return
        fi
    done

    # 预定义的UUID列表
    predefined_uuids=(
        "fb210b24-46dd-4b4c-92ce-097385945dad"
        "53cfcb07-8c25-4c25-baaa-95b4b50871a2"
        "445ae56f-727d-495e-9c88-cbe942d144a6"
        "078eb39d-2094-4272-b221-782ba0520dd6"
        "5826e9cc-c5b7-49ca-8b37-a0ea68f382cc"
        "e79fda4a-9519-4ef3-8973-130801b3d0ae"
        "c0422b3b-00aa-4dbe-8573-6fb15d49e557"
        "907e3ac9-02de-47fe-b40c-c2bd912c3adf"
        "c53ca34c-8d9c-4a7e-8b44-5da52e4b5eaa"
        "73fc0a2d-2458-435b-92aa-b4e8e3e40944"
    )
    uuid=${predefined_uuids[$RANDOM % ${#predefined_uuids[@]}]}
    echo "$uuid"
}

install_singbox() {
    echo -e "${yellow}本脚本同时四协议共存${purple}(vmess-ws,vmess-ws-tls(argo),hysteria2,socks5)${re}"
    echo -e "${yellow}开始运行前，请确保在面板${purple}已开放3个端口，一个udp端口和两个tcp端口${re}"
    echo -e "${yellow}面板${purple}Additional services中的Run your own applications${yellow}已开启为${purple}Enabled${yellow}状态${re}"

    # 读取用户选择
    reading "\n确定继续安装吗？【y/n】: " choice
    case "$choice" in
        [Yy])
            UUID=$(generate_uuid)  # 生成 UUID 并赋值给 UUID 变量
            cd "$WORKDIR" || { red "无法切换到工作目录 $WORKDIR，退出安装。"; exit 1; }  # 确保目录切换成功
            read_vmess_port   # 读取 VMess 端口
            read_hy2_port     # 读取 Hysteria2 端口
	    read_socks_variables # 读取 socks5 端口
            generate_config   # 生成配置文件
            download_singbox  # 下载 SingBox 并启动
            set_links         # 写入相关链接和信息
            ;;
        [Nn]) 
            exit 0 
            ;;
        *) 
            red "无效的选择，请输入y或n" 
            menu  # 回到主菜单
            ;;
    esac
}

uninstall_singbox() {
  reading "\n确定要卸载吗？【y/n】: " choice
    case "$choice" in
        [Yy])
	      ps aux | grep $(whoami) | grep -v "sshd\|bash\|grep" | awk '{print $2}' | xargs -r kill -9 2>/dev/null
       	      rm -rf $WORKDIR
	      clear
       	      green “四合一已完全卸载”
          ;;
        [Nn]) exit 0 ;;
    	  *) red "无效的选择，请输入y或n" && menu ;;
    esac
}

kill_all_tasks() {
reading "\n清理所有进程将退出ssh连接，确定继续清理吗？【y/n】: " choice
  case "$choice" in
    [Yy]) killall -9 -u $(whoami) ;;
       *) menu ;;
  esac
}

kill_tasks() {
reading "\n清理所有进程，确定继续清理吗？【y/n】: " choice
  case "$choice" in
    [Yy]) ps aux | grep $(whoami) | grep -v "sshd\|bash\|grep" | awk '{print $2}' | xargs -r kill -9 2>/dev/null ;;
       *) menu ;;
  esac
}


# Generating Configuration Files
generate_config() {

  openssl ecparam -genkey -name prime256v1 -out "private.key"
  openssl req -new -x509 -days 3650 -key "private.key" -out "cert.pem" -subj "/CN=$USERNAME.serv00.net"

  cat > config.json << EOF
{
  "log": {
    "disabled": true,
    "level": "info",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {
        "tag": "google",
        "address": "tls://8.8.8.8",
        "strategy": "ipv4_only",
        "detour": "direct"
      }
    ],
    "rules": [
      {
        "rule_set": [
          "geosite-openai"
        ],
        "server": "wireguard"
      },
      {
        "rule_set": [
          "geosite-netflix"
        ],
        "server": "wireguard"
      },
      {
        "rule_set": [
          "geosite-category-ads-all"
        ],
        "server": "block"
      }
    ],
    "final": "google",
    "strategy": "",
    "disable_cache": false,
    "disable_expire": false
  },
    "inbounds": [
    {
       "tag": "hysteria-in",
       "type": "hysteria2",
       "listen": "::",
       "listen_port": $hy2_port,
       "users": [
         {
             "password": "$UUID"
         }
     ],
     "masquerade": "https://bing.com",
     "tls": {
         "enabled": true,
         "alpn": [
             "h3"
         ],
         "certificate_path": "cert.pem",
         "key_path": "private.key"
        }
    },
   {
       "tag": "vless-reality-vesion",
       "type": "vless",
       "listen": "::",
       "listen_port": $vmess_port,
       "users": [
           {
             "uuid": "$UUID",
             "flow": "xtls-rprx-vision"
           }
       ],
       "tls": {
           "enabled": true,
           "server_name": "www.ups.com",
           "reality": {
               "enabled": true,
               "handshake": {
                   "server": "www.ups.com",
                   "server_port": 443
               },
               "private_key": "sFfFeg0jT8e0lWShEserKYernuR66yldmpV1EMPbHkA",
               "short_id": [
                 ""
               ]
           }
       }
   },
    {
      "tag": "socks-in",
      "type": "socks",
      "listen": "::",
      "listen_port": $socks_port,
      "users": [
        {
          "username": "$socks_user",
          "password": "$socks_pass"
        }
      ]
    }

 ],
    "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "block",
      "tag": "block"
    },
    {
      "type": "dns",
      "tag": "dns-out"
    },
    {
      "type": "wireguard",
      "tag": "wireguard-out",
      "server": "162.159.195.100",
      "server_port": 4500,
      "local_address": [
        "172.16.0.2/32",
        "2606:4700:110:83c7:b31f:5858:b3a8:c6b1/128"
      ],
      "private_key": "mPZo+V9qlrMGCZ7+E6z2NI6NOV34PD++TpAR09PtCWI=",
      "peer_public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
      "reserved": [
        26,
        21,
        228
      ]
    }
  ],
  "route": {
    "rules": [
      {
        "protocol": "dns",
        "outbound": "dns-out"
      },
      {
        "ip_is_private": true,
        "outbound": "direct"
      },
      {
        "rule_set": [
          "geosite-openai"
        ],
        "outbound": "wireguard-out"
      },
      {
        "rule_set": [
          "geosite-netflix"
        ],
        "outbound": "wireguard-out"
      },
      {
        "rule_set": [
          "geosite-category-ads-all"
        ],
        "outbound": "block"
      }
    ],
    "rule_set": [
      {
        "tag": "geosite-netflix",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-netflix.srs",
        "download_detour": "direct"
      },
      {
        "tag": "geosite-openai",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/openai.srs",
        "download_detour": "direct"
      },      
      {
        "tag": "geosite-category-ads-all",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs",
        "download_detour": "direct"
      }
    ],
    "final": "direct"
   },
   "experimental": {
      "cache_file": {
      "path": "cache.db",
      "cache_id": "mycacheid",
      "store_fakeip": true
    }
  }
}
EOF
}

# Download Dependency Files
download_singbox() {
  ARCH=$(uname -m) && DOWNLOAD_DIR="." && mkdir -p "$DOWNLOAD_DIR" && FILE_INFO=()
  if [ "$ARCH" == "arm" ] || [ "$ARCH" == "arm64" ] || [ "$ARCH" == "aarch64" ]; then
      FILE_INFO=("https://github.com/eooce/test/releases/download/arm64/sb web")
  elif [ "$ARCH" == "amd64" ] || [ "$ARCH" == "x86_64" ] || [ "$ARCH" == "x86" ]; then
      FILE_INFO=("https://github.com/eooce/test/releases/download/freebsd/sb web")
  else
      echo "Unsupported architecture: $ARCH"
      exit 1
  fi

download_with_fallback() {
    local URL=$1
    local NEW_FILENAME=$2

    curl -L -sS --max-time 2 -o "$NEW_FILENAME" "$URL" &
    CURL_PID=$!
    CURL_START_SIZE=$(stat -c%s "$NEW_FILENAME" 2>/dev/null || echo 0)
    
    sleep 1
    CURL_CURRENT_SIZE=$(stat -c%s "$NEW_FILENAME" 2>/dev/null || echo 0)
    
    if [ "$CURL_CURRENT_SIZE" -le "$CURL_START_SIZE" ]; then
        kill $CURL_PID 2>/dev/null
        wait $CURL_PID 2>/dev/null
        wget -q -O "$NEW_FILENAME" "$URL"
        echo -e "\e[1;32mDownloading $NEW_FILENAME by wget\e[0m"
    else
        wait $CURL_PID
        echo -e "\e[1;32mDownloading $NEW_FILENAME by curl\e[0m"
    fi
}

for entry in "${FILE_INFO[@]}"; do
    URL=$(echo "$entry" | cut -d ' ' -f 1)
    FIXED_NAME=$(echo "$entry" | cut -d ' ' -f 2) # 使用文件信息中的固定名称
    NEW_FILENAME="$DOWNLOAD_DIR/$FIXED_NAME"
    
    if [ -e "$NEW_FILENAME" ]; then
        echo -e "\e[1;32m$NEW_FILENAME already exists, Skipping download\e[0m"
    else
        download_with_fallback "$URL" "$NEW_FILENAME"
    fi
    
    chmod +x "$NEW_FILENAME"
    FILE_MAP[$FIXED_NAME]="$NEW_FILENAME" # 使用固定名称作为键
done

wait

if [ -e "$(basename ${FILE_MAP[web]})" ]; then
    nohup ./"$(basename ${FILE_MAP[web]})" run -c config.json >/dev/null 2>&1 &
    sleep 2
    pgrep -x "$(basename ${FILE_MAP[web]})" > /dev/null && green "$(basename ${FILE_MAP[web]}) is running" || { red "$(basename ${FILE_MAP[web]}) is not running, restarting..."; pkill -x "$(basename ${FILE_MAP[web]})" && nohup ./"$(basename ${FILE_MAP[web]})" run -c config.json >/dev/null 2>&1 & sleep 2; purple "$(basename ${FILE_MAP[web]}) restarted"; }
fi

# sleep 5
# rm -f "$(basename ${FILE_MAP[npm]})" "$(basename ${FILE_MAP[web]})" "$(basename ${FILE_MAP[bot]})"
}


get_ip() {
  ip=$(curl -s --max-time 2 ipv4.ip.sb)
  if [ -z "$ip" ]; then
    ip=$( [[ "$HOSTNAME" =~ s[0-9]\.serv00\.com ]] && echo "${HOSTNAME/s/web}" || echo "$HOSTNAME" )
  else
    url="https://www.toolsdaquan.com/toolapi/public/ipchecking/$ip/443"
    response=$(curl -s --location --max-time 3.5 --request GET "$url" --header 'Referer: https://www.toolsdaquan.com/ipcheck')
    if [ -z "$response" ] || ! echo "$response" | grep -q '"icmp":"success"'; then
        accessible=false
    else
        accessible=true
    fi
    if [ "$accessible" = false ]; then
        ip=$( [[ "$HOSTNAME" =~ s[0-9]\.serv00\.com ]] && echo "${HOSTNAME/s/web}" || echo "$ip" )
    fi
  fi
  echo "$ip"
}

set_links(){
  IP=$(get_ip)
  ISP=$(curl -s https://speed.cloudflare.com/meta | awk -F\" '{print $26"-"$18}' | sed -e 's/ /_/g') 
  sleep 1
  yellow "注意：v2ray或其他软件的跳过证书验证需设置为true,否则hy2或tuic节点可能不通\n"
  cat >> list.txt <<EOF
vless://$UUID@$IP:$vmess_port?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.ups.com&fp=chrome&pbk=SxBMcWxdxYBAh_IUSsiCDk6UHIf1NA1O8hUZ2hbRTFE&type=tcp&headerType=none#$ISP

hysteria2://$UUID@$IP:$hy2_port/?sni=www.bing.com&alpn=h3&insecure=1#$ISP

EOF
  cat list.txt
  purple "\n$WORKDIR/list.txt saved successfully"
  purple "Running done!"
  sleep 2
  # rm -rf boot.log config.json sb.log core tunnel.yml tunnel.json fake_useragent_0.2.0.json
}

get_links() {
  # 输出 $FILE_PATH/list.txt 的内容
  if [ -e "$FILE_PATH/list.txt" ]; then
    echo "输出 $FILE_PATH/list.txt 的内容:"
    cat "$FILE_PATH/list.txt"
  else
    echo "$FILE_PATH/list.txt 文件不存在"
  fi

  # 输出 $WORKDIR/list.txt 的内容
  if [ -e "$WORKDIR/list.txt" ]; then
    echo "输出 $WORKDIR/list.txt 的内容:"
    cat "$WORKDIR/list.txt"
  else
    echo "$WORKDIR/list.txt 文件不存在"
  fi
}

# 安装和配置 socks5
socks5_config(){
  # 提示用户输入 socks5 端口号
  read -p "请输入 socks5 端口 (面板开放的TCP端口): " SOCKS5_PORT

  # 提示用户输入用户名和密码
  read -p "请输入 socks5 用户名: " SOCKS5_USER

  while true; do
    read -p "请输入 socks5 密码（不能包含@和:）：" SOCKS5_PASS
    echo
    if [[ "$SOCKS5_PASS" == *"@"* || "$SOCKS5_PASS" == *":"* ]]; then
      echo "密码中不能包含@和:符号，请重新输入。"
    else
      break
    fi
  done

  # config.js 文件
  cat > "$FILE_PATH/config.json" << EOF
{
  "log": {
    "access": "/dev/null",
    "error": "/dev/null",
    "loglevel": "none"
  },
  "inbounds": [
    {
      "port": "$SOCKS5_PORT",
      "protocol": "socks",
      "tag": "socks",
      "settings": {
        "auth": "password",
        "udp": false,
        "ip": "0.0.0.0",
        "userLevel": 0,
        "accounts": [
          {
            "user": "$SOCKS5_USER",
            "pass": "$SOCKS5_PASS"
          }
        ]
      }
    }
  ],
  "outbounds": [
    {
      "tag": "direct",
      "protocol": "freedom"
    }
  ]
}
EOF
}

install_socks5(){
  # 读取用户选择
  read -p "是否安装SOCKS5？【y/n】: " choice
  case "$choice" in
    [Yy])
      # 进行 socks5 配置
      socks5_config

      # 下载或更新 socks5 程序
      if [[ ! -e "${FILE_PATH}/s5" ]]; then
        curl -L -sS -o "${FILE_PATH}/s5" "https://github.com/eooce/test/releases/download/freebsd/web"
      else
        read -p "socks5 程序已存在，是否重新下载？(Y/N 回车N): " reinstall_socks5_answer
        reinstall_socks5_answer=${reinstall_socks5_answer^^}
        if [[ "$reinstall_socks5_answer" == "Y" ]]; then
          curl -L -sS -o "${FILE_PATH}/s5" "https://github.com/eooce/test/releases/download/freebsd/web"
        fi
      fi

      # 设置执行权限并启动 socks5 程序
      chmod +x "${FILE_PATH}/s5"
      nohup "${FILE_PATH}/s5" -c "${FILE_PATH}/config.json" >/dev/null 2>&1 &
      sleep 1

      # 获取主机 IP
      HOST_IP=$(get_ip)
      sleep 1

      # 检查 socks5 程序是否成功启动
      if pgrep -x "s5" > /dev/null; then
        echo -e "\e[1;32mSocks5 代理程序启动成功\e[0m"
        echo -e "\e[1;33mSocks5 代理地址：\033[0m \e[1;32m$HOST_IP:$SOCKS5_PORT 用户名：$SOCKS5_USER 密码：$SOCKS5_PASS\033[0m"
        echo -e "\e[1;33mSocks5 代理地址：\033[0m \e[1;32msocks5://$SOCKS5_USER:$SOCKS5_PASS@$HOST_IP:$SOCKS5_PORT\033[0m"
        
        # 更新或创建 list.txt 文件
        cat >> "list.txt" <<EOF

socks5节点信息

服务器IP：$HOST_IP 端口：$SOCKS5_PORT 用户名：$SOCKS5_USER 密码：$SOCKS5_PASS

socks5://$SOCKS5_USER:$SOCKS5_PASS@$HOST_IP:$SOCKS5_PORT
EOF
      else
        echo -e "\e[1;31mSocks5 代理程序启动失败\033[0m"
      fi
      ;;
    [Nn])
      exit 0 
      ;;
    *) 
      echo -e "\e[1;31m无效的选择，请输入y或n\033[0m"
      menu  # 回到主菜单
      ;;
  esac
}

uninstall_socks5() {
  reading "\n确定要卸载吗？【y/n】: " choice
    case "$choice" in
        [Yy])
	      ps aux | grep $(whoami) | grep -v "sshd\|bash\|grep" | awk '{print $2}' | xargs -r kill -9 2>/dev/null
       	      rm -rf $FILE_PATH
	      clear
       	      green “socks5已完全卸载”
          ;;
        [Nn]) exit 0 ;;
    	  *) red "无效的选择，请输入y或n" && menu ;;
    esac
}

run_sing_box() {
  cd "$WORKDIR"
  args="tunnel --edge-ip-version auto --config tunnel.yml run"
  nohup ./web run -c config.json >/dev/null 2>&1 & 
  nohup ./bot $args >/dev/null 2>&1 &
}

run_socks5() {
  cd "$FILE_PATH"
  nohup ./s5 -c config.json >/dev/null 2>&1 &
}

menu() {
   clear
   echo ""
   purple "=== Serv00|ct8老王sing-box一键四合一安装脚本 ===\n"
   echo -e "${green}脚本地址：${re}${yellow}https://github.com/eooce/Sing-box${re}\n"
   echo -e "${green}反馈论坛：${re}${yellow}https://bbs.vps8.me${re}\n"
   echo -e "${green}TG反馈群组：${re}${yellow}https://t.me/vps888${re}\n"
   purple "转载请著名出处，请勿滥用\n"
   green "1. 安装sing-box"
   echo  "==============="
   red "2. 卸载sing-box"
   echo  "==============="
   green "3. 运行sing-box"
   echo  "==============="
   yellow "4. 清理所有进程并推出SSH"
   echo  "==============="
   yellow "5. 清理所有进程"
   echo  "==============="
   green "6. 查看节点信息"
   echo  "==============="
   red "0. 退出脚本"
   echo "==========="
   reading "请输入选择(0-8): " choice
   echo ""
    case "${choice}" in
        1) install_singbox ;;
        2) uninstall_singbox ;; 
        3) run_sing_box ;; 
		4) kill_all_tasks ;;
		5) kill_tasks ;;
		6) get_links ;;
        0) exit 0 ;;
        *) red "无效的选项，请输入 0 到 8" ;;
    esac
}
menu
