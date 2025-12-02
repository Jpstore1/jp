#!/bin/bash
Green="\e[92;1m"
RED="\033[31m"
YELLOW="\033[33m"
BLUE="\033[36m"
FONT="\033[0m"
GREENBG="\033[42;37m"
REDBG="\033[41;37m"
OK="${Green}--->${FONT}"
ERROR="${RED}[ERROR]${FONT}"
GRAY="\e[1;30m"
NC='\e[0m'
red='\e[1;31m'
green='\e[0;32m'
# ===================
clear
  # // Exporint IP AddressInformation
export IP=$( curl -sS icanhazip.com || echo "" )

# // Clear Data
clear
clear && clear && clear
clear;clear;clear

  # // Banner
echo -e "${YELLOW}----------------------------------------------------------${NC}"
echo -e "  Auther : ${green}VPN - JP OFFICIAL STORE® ${NC}${YELLOW}(${NC} ${green} XPRESS ${NC}${YELLOW})${NC}"
echo -e "${YELLOW}----------------------------------------------------------${NC}"
echo ""
sleep 2
###### IZIN SC 

# // Checking Os Architecture
if [[ $( uname -m | awk '{print $1}' ) == "x86_64" ]]; then
    echo -e "${OK} Your Architecture Is Supported ( ${green}$( uname -m )${NC} )"
else
    echo -e "${ERROR} Your Architecture Is Not Supported ( ${YELLOW}$( uname -m )${NC} )"
    exit 1
fi

# // Checking System
OS_ID=$(awk -F= '/^ID=/{print $2}' /etc/os-release 2>/dev/null | tr -d '"' || echo "")
PRETTY_NAME=$(awk -F= '/^PRETTY_NAME=/{print $2}' /etc/os-release 2>/dev/null | tr -d '"' || echo "")
if [[ "$OS_ID" == "ubuntu" ]]; then
    echo -e "${OK} Your OS Is Supported ( ${green}${PRETTY_NAME}${NC} )"
elif [[ "$OS_ID" == "debian" ]]; then
    echo -e "${OK} Your OS Is Supported ( ${green}${PRETTY_NAME}${NC} )"
else
    echo -e "${ERROR} Your OS Is Not Supported ( ${YELLOW}${PRETTY_NAME}${NC} )"
    exit 1
fi

# // IP Address Validating
if [[ -z "$IP" ]]; then
    echo -e "${ERROR} IP Address ( ${YELLOW}Not Detected${NC} )"
else
    echo -e "${OK} IP Address ( ${green}$IP${NC} )"
fi

# // Validate Successfull
echo ""
read -p "$( echo -e "Press ${GRAY}[ ${NC}${green}Enter${NC} ${GRAY}]${NC} For Starting Installation") "
echo ""
clear
if [ "${EUID}" -ne 0 ]; then
		echo "You need to run this script as root"
		exit 1
fi
if command -v systemd-detect-virt >/dev/null 2>&1 && [ "$(systemd-detect-virt)" == "openvz" ]; then
		echo "OpenVZ is not supported"
		exit 1
fi
red='\e[1;31m'
green='\e[0;32m'
NC='\e[0m'
#IZIN SCRIPT
MYIP=$(curl -sS ipv4.icanhazip.com || echo "$IP")
echo -e "\e[32mloading...\e[0m"
clear
apt install -y ruby || true
if command -v gem >/dev/null 2>&1; then
  gem install lolcat || true
fi
apt install -y wondershaper || true
clear
# REPO    
    REPO="https://raw.githubusercontent.com/Jpstore1/jp/main/"

####
start=$(date +%s)
secs_to_human() {
    echo "Installation time : $((${1} / 3600)) hours $(((${1} / 60) % 60)) minute's $((${1} % 60)) seconds"
}
### Status
function print_ok() {
    echo -e "${OK} ${BLUE} $1 ${FONT}"
}
function print_install() {
	echo -e "${green} =============================== ${FONT}"
    echo -e "${YELLOW} # $1 ${FONT}"
	echo -e "${green} =============================== ${FONT}"
    sleep 1
}

function print_error() {
    echo -e "${ERROR} ${REDBG} $1 ${FONT}"
}

function print_success() {
    if [[ 0 -eq $? ]]; then
		echo -e "${green} =============================== ${FONT}"
        echo -e "${Green:-$Green} # $1 berhasil dipasang"
		echo -e "${green} =============================== ${FONT}"
        sleep 2
    fi
}

### Cek root
function is_root() {
    if [[ 0 == "$UID" ]]; then
        print_ok "Root user Start installation process"
    else
        print_error "The current user is not the root user, please switch to the root user and run the script again"
    fi

}

# Buat direktori xray
print_install "Membuat direktori xray"
    mkdir -p /etc/xray
    curl -s ifconfig.me > /etc/xray/ipvps || true
    touch /etc/xray/domain
    mkdir -p /var/log/xray
    chown www-data:www-data /var/log/xray 2>/dev/null || true
    chmod +x /var/log/xray 2>/dev/null || true
    touch /var/log/xray/access.log
    touch /var/log/xray/error.log
    mkdir -p /var/lib/kyt >/dev/null 2>&1
    # // Ram Information
    mem_used=0
    mem_total=0
    while IFS=":" read -r a b; do
    case $a in
        "MemTotal") ((mem_used+=${b/kB})); mem_total="${b/kB}" ;;
        "Shmem") ((mem_used+=${b/kB}))  ;;
        "MemFree" | "Buffers" | "Cached" | "SReclaimable")
        mem_used="$((mem_used-=${b/kB}))"
    ;;
    esac
    done < /proc/meminfo 2>/dev/null || true
    Ram_Usage="$((mem_used / 1024))"
    Ram_Total="$((mem_total / 1024))"
    export tanggal=$(date -d "0 days" +"%d-%m-%Y - %X" 2>/dev/null || date +"%d-%m-%Y - %X")
    export OS_Name=$( cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/PRETTY_NAME//g' | sed 's/=//g' | sed 's/"//g' 2>/dev/null || echo "$PRETTY_NAME" )
    export Kernel=$( uname -r )
    export Arch=$( uname -m )
    export IP=$( curl -s https://ipinfo.io/ip/ || echo "$MYIP" )

# Change Environment System
function first_setup(){
    timedatectl set-timezone Asia/Jakarta 2>/dev/null || true
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    print_success "Directory Xray"
    if [[ "$OS_ID" == "ubuntu" ]]; then
    echo "Setup Dependencies ${PRETTY_NAME}"
    sudo apt update -y || true
    apt-get install --no-install-recommends software-properties-common -y || true
    # try PPA, fallback to default haproxy package if PPA fails
    add-apt-repository ppa:vbernat/haproxy-2.0 -y >/dev/null 2>&1 || true
    apt-get -y install haproxy || true
elif [[ "$OS_ID" == "debian" ]]; then
    echo "Setup Dependencies For OS Is ${PRETTY_NAME}"
    curl -fsSL https://haproxy.debian.net/bernat.debian.org.gpg |
        gpg --dearmor >/usr/share/keyrings/haproxy.debian.net.gpg 2>/dev/null || true
    echo deb "[signed-by=/usr/share/keyrings/haproxy.debian.net.gpg]" \
        http://haproxy.debian.net buster-backports-1.8 main \
        >/etc/apt/sources.list.d/haproxy.list
    sudo apt-get update -y || true
    apt-get -y install haproxy || true
else
    echo -e " Your OS Is Not Supported (${PRETTY_NAME} )"
    exit 1
fi
}

# GEO PROJECT
clear
function nginx_install() {
    # // Checking System
    if [[ "$OS_ID" == "ubuntu" ]]; then
        print_install "Setup nginx For OS Is ${PRETTY_NAME}"
        # // sudo add-apt-repository ppa:nginx/stable -y 
        sudo apt-get install -y nginx || true
    elif [[ "$OS_ID" == "debian" ]]; then
        print_success "Setup nginx For OS Is ${PRETTY_NAME}"
        apt -y install nginx || true
    else
        echo -e " Your OS Is Not Supported ( ${YELLOW}${PRETTY_NAME}${FONT} )"
        # // exit 1
    fi
}

# Update and remove packages
function base_package() {
    clear
    ########
    print_install "Menginstall Packet Yang Dibutuhkan"
    apt install -y zip pwgen openssl netcat socat cron bash-completion || true
    apt install -y figlet || true
    apt update -y || true
    apt upgrade -y || true
    apt dist-upgrade -y || true
    # chrony handling
    if command -v chronyd >/dev/null 2>&1; then
        systemctl enable chronyd || true
        systemctl restart chronyd || true
        systemctl enable chrony || true
        systemctl restart chrony || true
        chronyc sourcestats -v || true
        chronyc tracking -v || true
    fi
    apt install -y ntpdate || true
    ntpdate pool.ntp.org || true
    apt install -y sudo || true
    sudo apt-get clean all || true
    sudo apt-get autoremove -y || true
    sudo apt-get install -y debconf-utils || true
    sudo apt-get remove --purge -y exim4 || true
    sudo apt-get remove --purge -y ufw firewalld || true
    sudo apt-get install -y --no-install-recommends software-properties-common || true
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    sudo apt-get install -y speedtest-cli vnstat libnss3-dev libnspr4-dev pkg-config libpam0g-dev libcap-ng-dev libcap-ng-utils libselinux1-dev libcurl4-nss-dev flex bison make libnss3-tools libevent-dev bc rsyslog dos2unix zlib1g-dev libssl-dev libsqlite3-dev sed dirmngr libxml-parser-perl build-essential gcc g++ python htop lsof tar wget curl ruby zip unzip p7zip-full python3-pip libc6 util-linux build-essential msmtp-mta ca-certificates bsd-mailx iptables iptables-persistent netfilter-persistent net-tools openssl ca-certificates gnupg gnupg2 ca-certificates lsb-release gcc shc make cmake git screen socat xz-utils apt-transport-https gnupg1 dnsutils cron bash-completion ntpdate chrony jq openvpn easy-rsa || true
    print_success "Packet Yang Dibutuhkan"
    
}
clear
# Fungsi input domain
function pasang_domain() {
echo -e ""
clear
    echo -e "   .----------------------------------."
echo -e "   |\e[1;32mPlease Select a Domain Type Below \e[0m|"
echo -e "   '----------------------------------'"
echo -e "     \e[1;32m1)\e[0m Menggunakan Domain Sendiri"
echo -e "     \e[1;32m2)\e[0m Menggunakan Domain Random"
echo -e "   ------------------------------------"
read -p "   Please select numbers 1-2 or Any Button(Random) : " host
echo ""
if [[ $host == "1" ]]; then
echo -e "   \e[1;32mPlease Enter Your Subdomain $NC"
read -p "   Subdomain: " host1
echo "IP=" >> /var/lib/kyt/ipvps.conf
echo $host1 > /etc/xray/domain
echo $host1 > /root/domain
echo ""
elif [[ $host == "2" ]]; then
#install cf
wget ${REPO}files/cf.sh -O /root/cf.sh && chmod +x /root/cf.sh && /root/cf.sh || true
rm -f /root/cf.sh
clear
else
print_install "Random Subdomain/Domain is Used"
clear
    fi
}

clear
#GANTI PASSWORD DEFAULT
restart_system(){
#IZIN SCRIPT
MYIP=$(curl -sS ipv4.icanhazip.com || echo "$IP")
echo -e "\e[32mloading...\e[0m" 
clear
izinsc="https://raw.githubusercontent.com/Jpstore1/jp/main/Regist"
# USERNAME
rm -f /usr/bin/user 2>/dev/null || true
username=$(curl -fsS $izinsc 2>/dev/null | grep "$MYIP" | awk '{print $2}' || echo "")
echo "$username" >/usr/bin/user
expx=$(curl -fsS $izinsc 2>/dev/null | grep "$MYIP" | awk '{print $3}' || echo "")
echo "$expx" >/usr/bin/e
# DETAIL ORDER
username=$(cat /usr/bin/user 2>/dev/null || echo "")
oid=$(cat /usr/bin/ver 2>/dev/null || echo "")
exp=$(cat /usr/bin/e 2>/dev/null || echo "")
clear
# CERTIFICATE STATUS
today=$(date +'%Y-%m-%d')
Exp1=$(curl -fsS $izinsc 2>/dev/null | grep "$MYIP" | awk '{print $4}' || echo "")
valid="${Exp1:-$exp}"
# safe date parsing
if [[ -n "$valid" ]]; then
    d1=$(date -d "$valid" +%s 2>/dev/null || echo 0)
else
    d1=0
fi
d2=$(date -d "$today" +%s 2>/dev/null || echo 0)
if [[ $d2 -gt 0 && $d1 -gt 0 ]]; then
    certifacate=$(((d1 - d2) / 86400))
else
    certifacate=0
fi
# VPS Information
DATE=$(date +'%Y-%m-%d')
datediff() {
    d1=$(date -d "$1" +%s 2>/dev/null || echo 0)
    d2=$(date -d "$2" +%s 2>/dev/null || echo 0)
    echo -e "$COLOR1 $NC Expiry In   : $(( (d1 - d2) / 86400 )) Days"
}
mai="datediff \"$valid\" \"$DATE\""

# Status Expired Active
Info="(${green}Active${NC})"
Error="(${RED}ExpiRED${NC})"
today=`date -d "0 days" +"%Y-%m-%d"`
Exp1=$(curl -fsS $izinsc 2>/dev/null | grep "$MYIP" | awk '{print $4}' || echo "")
if [[ -n "$Exp1" && "$today" < "$Exp1" ]]; then
sts="${Info}"
else
sts="${Error}"
fi
TIMES="10"
CHATID="1626302370"
KEY="${KEY:-}"   # safe default: empty unless set by user
URL="https://api.telegram.org/bot$KEY/sendMessage"
    TIMEZONE=$(printf '%(%H:%M:%S)T')
    # Ensure domain and ISP have fallback values
    domain=$(cat /root/domain 2>/dev/null || echo "$MYIP")
    ISP=$(cat /etc/xray/isp 2>/dev/null || curl -fsS ipinfo.io/org 2>/dev/null | cut -d " " -f 2-10 || echo "Unknown")
    TEXT="
<code>────────────────────</code>
<b>⚡AUTOSCRIPT PREMIUM⚡</b>
<code>────────────────────</code>
<code>User     :</code><code>$username</code>
<code>Domain   :</code><code>$domain</code>
<code>IPVPS    :</code><code>$MYIP</code>
<code>ISP      :</code><code>$ISP</code>
<code>Exp Sc.  :</code><code>$exp</code>
<code>────────────────────</code>
<b> 🇮🇩🇮🇩TUNNELING🇮🇩🇮🇩</b>
<code>────────────────────</code>
<i>Automatic Notifications From Github</i>
"
    # send only if KEY present
    if [[ -n "$KEY" ]]; then
        curl -s --max-time $TIMES -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL >/dev/null || true
    fi
}
clear
# Pasang SSL
function pasang_ssl() {
clear
print_install "Memasang SSL Pada Domain"
    rm -rf /etc/xray/xray.key 2>/dev/null || true
    rm -rf /etc/xray/xray.crt 2>/dev/null || true
    domain=$(cat /root/domain 2>/dev/null || echo "")
    # safer stop of process listening on 80
    STOPPID=$(lsof -t -i:80 2>/dev/null || true)
    if [[ -n "$STOPPID" ]]; then
        # find service name from pid
        STOPWEBSERVER=$(ps -p "$STOPPID" -o comm= | head -n1 2>/dev/null || echo "")
        if [[ -n "$STOPWEBSERVER" && "$(systemctl list-units --type=service --all --no-legend | grep -q "$STOPWEBSERVER" && echo 1 || echo 0)" == "1" ]]; then
            systemctl stop "$STOPWEBSERVER" 2>/dev/null || kill -9 "$STOPPID" 2>/dev/null || true
        else
            kill -9 "$STOPPID" 2>/dev/null || true
        fi
    fi
    systemctl stop nginx 2>/dev/null || true
    rm -rf /root/.acme.sh 2>/dev/null || true
    mkdir -p /root/.acme.sh 2>/dev/null || true
    # Use official acme.sh installer (more reliable)
    curl -fsSL https://get.acme.sh | sh || true
    if [[ -f "$HOME/.acme.sh/acme.sh" ]]; then
        ACME_BIN="$HOME/.acme.sh/acme.sh"
    elif [[ -f /root/.acme.sh/acme.sh ]]; then
        ACME_BIN="/root/.acme.sh/acme.sh"
    else
        ACME_BIN=""
    fi
    if [[ -n "$ACME_BIN" ]]; then
        $ACME_BIN --set-default-ca --server letsencrypt || true
        $ACME_BIN --issue -d "$domain" --standalone -k ec-256 || true
        $ACME_BIN --installcert -d "$domain" --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc || true
    else
        echo -e "${ERROR} acme.sh not found, cannot issue certificate"
    fi
    chmod 600 /etc/xray/xray.key 2>/dev/null || true
    print_success "SSL Certificate"
}

function make_folder_xray() {
rm -rf /etc/vmess/.vmess.db 2>/dev/null || true
    rm -rf /etc/vless/.vless.db 2>/dev/null || true
    rm -rf /etc/trojan/.trojan.db 2>/dev/null || true
    rm -rf /etc/shadowsocks/.shadowsocks.db 2>/dev/null || true
    rm -rf /etc/ssh/.ssh.db 2>/dev/null || true
    rm -rf /etc/bot/.bot.db 2>/dev/null || true
    rm -rf /etc/user-create/user.log 2>/dev/null || true
    mkdir -p /etc/bot
    mkdir -p /etc/xray
    mkdir -p /etc/vmess
    mkdir -p /etc/vless
    mkdir -p /etc/trojan
    mkdir -p /etc/shadowsocks
    mkdir -p /etc/ssh
    mkdir -p /usr/bin/xray/
    mkdir -p /var/log/xray/
    mkdir -p /var/www/html
    mkdir -p /etc/kyt/limit/vmess/ip
    mkdir -p /etc/kyt/limit/vless/ip
    mkdir -p /etc/kyt/limit/trojan/ip
    mkdir -p /etc/kyt/limit/ssh/ip
    mkdir -p /etc/limit/vmess
    mkdir -p /etc/limit/vless
    mkdir -p /etc/limit/trojan
    mkdir -p /etc/limit/ssh
    mkdir -p /etc/user-create
    chmod +x /var/log/xray 2>/dev/null || true
    touch /etc/xray/domain
    touch /var/log/xray/access.log
    touch /var/log/xray/error.log
    touch /etc/vmess/.vmess.db
    touch /etc/vless/.vless.db
    touch /etc/trojan/.trojan.db
    touch /etc/shadowsocks/.shadowsocks.db
    touch /etc/ssh/.ssh.db
    touch /etc/bot/.bot.db
    echo "& plughin Account" >>/etc/vmess/.vmess.db
    echo "& plughin Account" >>/etc/vless/.vless.db
    echo "& plughin Account" >>/etc/trojan/.trojan.db
    echo "& plughin Account" >>/etc/shadowsocks/.shadowsocks.db
    echo "& plughin Account" >>/etc/ssh/.ssh.db
    echo "echo -e 'Vps Config User Account'" >> /etc/user-create/user.log
    }
#Instal Xray
function install_xray() {
clear
    print_install "Core Xray 1.8.1 Latest Version"
    domainSock_dir="/run/xray";! [ -d $domainSock_dir ] && mkdir  $domainSock_dir
    chown www-data:www-data $domainSock_dir 2>/dev/null || true
    
    # / / Ambil Xray Core Version Terbaru
latest_version="$(curl -fsS https://api.github.com/repos/XTLS/Xray-core/releases 2>/dev/null | grep -E 'tag_name' | sed -E 's/.*\"v?([^"]+)\".*/\1/' | head -n 1 || echo "")"
if [[ -n "$latest_version" ]]; then
    bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version "$latest_version" || true
else
    bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data || true
fi
 
    # // Ambil Config Server
    wget -O /etc/xray/config.json "${REPO}config/config.json" >/dev/null 2>&1 || true
    wget -O /etc/systemd/system/runn.service "${REPO}files/runn.service" >/dev/null 2>&1 || true
    #chmod +x /usr/local/bin/xray
    domain=$(cat /etc/xray/domain 2>/dev/null || echo "")
    IPVS=$(cat /etc/xray/ipvps 2>/dev/null || echo "$MYIP")
    print_success "Core Xray 1.8.1 Latest Version"
    
    # Settings UP Nginix Server
    clear
    curl -fsS ipinfo.io/city >>/etc/xray/city 2>/dev/null || true
    curl -fsS ipinfo.io/org | cut -d " " -f 2-10 >>/etc/xray/isp 2>/dev/null || true
    print_install "Memasang Konfigurasi Packet"
    wget -O /etc/haproxy/haproxy.cfg "${REPO}config/haproxy.cfg" >/dev/null 2>&1 || true
    wget -O /etc/nginx/conf.d/xray.conf "${REPO}config/xray.conf" >/dev/null 2>&1 || true
    if [[ -n "$domain" ]]; then
        sed -i "s/xxx/${domain}/g" /etc/haproxy/haproxy.cfg 2>/dev/null || true
        sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf 2>/dev/null || true
    fi
    curl -fsS ${REPO}config/nginx.conf > /etc/nginx/nginx.conf 2>/dev/null || true
    
cat /etc/xray/xray.crt /etc/xray/xray.key | tee /etc/haproxy/hap.pem >/dev/null 2>&1 || true

    # > Set Permission
    chmod +x /etc/systemd/system/runn.service 2>/dev/null || true

    # > Create Service
    rm -rf /etc/systemd/system/xray.service.d 2>/dev/null || true
    cat >/etc/systemd/system/xray.service <<EOF
Description=Xray Service
Documentation=https://github.com
After=network.target nss-lookup.target

[Service]
User=www-data
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target

EOF
print_success "Konfigurasi Packet"
}

function ssh(){
clear
print_install "Memasang Password SSH"
    wget -q -O /etc/pam.d/common-password "${REPO}files/password" >/dev/null 2>&1 || true
chmod +x /etc/pam.d/common-password 2>/dev/null || true

    DEBIAN_FRONTEND=noninteractive dpkg-reconfigure keyboard-configuration 2>/dev/null || true
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/altgr select The default for the keyboard layout"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/compose select No compose key"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/ctrl_alt_bksp boolean false"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layoutcode string de"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layout select English"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/modelcode string pc105"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/model select Generic 105-key (Intl) PC"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/optionscode string "
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/store_defaults_in_debconf_db boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/switch select No temporary switch"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/toggle select No toggling"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_config_layout boolean true"
    debconf-set-selections <<<"keyb
