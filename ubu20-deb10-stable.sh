#!/bin/bash 
 
# ========================================== 
# Color definitions 
# ========================================== 
Green="\e[92;1m" 
RED="\033[31m" 
YELLOW="\033[33m" 
BLUE="\033[36m" 
FONT="\033[0m" 
OK="${Green}--->${FONT}" 
ERROR="${RED}[ERROR]${FONT}" 
GRAY="\e[1;30m" 
NC='\e[0m' 
EROR="${RED}[EROR]${FONT}" 
 
# ========================================== 
# Global variables 
# ========================================== 
REPO="https://raw.githubusercontent.com/Jpstore1/jp/main/" 
start=$(date +%s) 
 
# ========================================== 
# Utility functions 
# ========================================== 
secs_to_human() { 
    echo "Installation time: $((${1} / 3600)) hours $(((${1} / 60) % 60)) minutes $((${1} % 60)) seconds" 
} 
 
print_ok() { 
    echo -e "${OK} ${BLUE} $1 ${FONT}" 
} 
 
print_install() { 
    echo -e "${Green}===============================${FONT}" 
    echo -e "${YELLOW} # $1 ${FONT}" 
    echo -e "${Green}===============================${FONT}" 
    sleep 1 
} 
 
print_error() { 
    echo -e "${ERROR} ${RED} $1 ${FONT}" 
} 
 
print_success() { 
    echo -e "${Green}===============================${FONT}" 
    echo -e "${Green} ✓ $1 berhasil dipasang ${FONT}" 
    echo -e "${Green}===============================${FONT}" 
    sleep 2 
} 
 
is_root() { 
    if [[ $EUID -ne 0 ]]; then 
        print_error "Script harus dijalankan sebagai root" 
        exit 1 
    fi 
    print_ok "Root access confirmed" 
} 
 
get_os_info() { 
    OS_ID=$(grep -w ID /etc/os-release | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g') 
    OS_PRETTY=$(grep -w PRETTY_NAME /etc/os-release | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g') 
    ARCH=$(uname -m) 
    IP=$(curl -sS ifconfig.me) 
} 
 
check_system() { 
    clear 
    print_install "Checking system compatibility" 
     
    # Architecture check 
    if [[ $ARCH != "x86_64" ]]; then 
        print_error "Architecture tidak didukung: $ARCH" 
        exit 1 
    fi 
    print_ok "Architecture: $ARCH ✓" 
     
    # OS check 
    if [[ "$OS_ID" != "ubuntu" && "$OS_ID" != "debian" ]]; then 
        print_error "OS tidak didukung: $OS_PRETTY" 
        exit 1 
    fi 
    print_ok "OS: $OS_PRETTY ✓" 
     
    # IP check 
    if [[ -z "$IP" ]]; then 
        print_error "IP tidak terdeteksi" 
        exit 1 
    fi 
    print_ok "IP: $IP ✓" 
     
    # Virtualization check 
    if [[ "$(systemd-detect-virt)" == "openvz" ]]; then 
        print_error "OpenVZ tidak didukung" 
        exit 1 
    fi 
    print_ok "Virtualization check passed ✓" 
} 
 
show_banner() { 
    clear 
    echo -e "${YELLOW}----------------------------------------------------------${NC}" 
    echo -e "  Author: ${Green}VPN - JP OFFICIAL STORE® ${NC}${YELLOW}(${NC} ${Green} XPRESS ${NC}${YELLOW})${NC}" 
    echo -e "${YELLOW}----------------------------------------------------------${NC}" 
    echo "" 
} 
 
# ========================================== 
# Main installation functions 
# ========================================== 
install_base_packages() { 
    print_install "Installing base packages" 
    apt update -y 
    apt install -y curl wget unzip zip openssl netcat socat cron bash-completion figlet \ 
                   ruby wondershaper htop lsof tar screen git jq dnsutils ntpdate chrony \ 
                   iptables-persistent netfilter-persistent net-tools ca-certificates \ 
                   gnupg gnupg2 lsb-release build-essential gcc make cmake 
    print_success "Base packages" 
} 
 
setup_system() { 
    print_install "System setup" 
     
    # Timezone 
    timedatectl set-timezone Asia/Jakarta 
     
    # NTP sync 
    systemctl enable chrony 
    systemctl restart chrony 
    ntpdate pool.ntp.org 
     
    # Disable IPv6 
    echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf 
    sysctl -p 
     
    # Cleanup 
    apt autoremove -y 
    apt autoclean 
    print_success "System setup" 
} 
 
setup_directories() { 
    print_install "Creating directories" 
    mkdir -p /etc/{xray,vmess,vless,trojan,shadowsocks,ssh,bot,kyt/limit/{vmess,vless,trojan,ssh}/ip,limit/{vmess,vless,trojan,ssh},user-create} 
    mkdir -p /var/{log/xray,lib/kyt,www/html} /usr/bin/xray /run/xray 
     
    # Permissions 
    chown www-data:www-data /var/log/xray /run/xray 
    chmod 755 /var/log/xray /run/xray 
     
    # Initialize files 
    touch /etc/xray/{domain,ipvps,city,isp} 
    touch /var/log/xray/{access,error}.log 
    for db in vmess vless trojan shadowsocks ssh bot; do 
        touch /etc/$db/.$db.db 
        echo "& plugin Account" >> /etc/$db/.$db.db 
    done 
    echo "VPS Config User Account" > /etc/user-create/user.log 
     
    curl -s ifconfig.me > /etc/xray/ipvps 
    print_success "Directories created" 
} 
 
setup_domain() { 
    clear 
    echo -e "   .----------------------------------." 
    echo -e "   |${Green}Please Select a Domain Type Below${FONT}|" 
    echo -e "   '----------------------------------'" 
    echo -e "     ${Green}1)${FONT} Menggunakan Domain Sendiri" 
    echo -e "     ${Green}2)${FONT} Menggunakan Domain Random" 
    echo -e "   ------------------------------------" 
     
    read -p "   Pilih (1-2) atau Enter untuk Random: " choice 
     
    case $choice in 
        1) 
            read -p "   Subdomain: " domain 
            echo "$domain" > /etc/xray/domain 
            echo "$domain" > /root/domain 
            ;; 
        2) 
            wget "${REPO}files/cf.sh" && chmod +x cf.sh && ./cf.sh 
            rm -f cf.sh 
            ;; 
        *) 
            print_install "Menggunakan Random Subdomain" 
            wget "${REPO}files/cf.sh" && chmod +x cf.sh && ./cf.sh 
            rm -f cf.sh 
            ;; 
    esac 
} 
 
install_ssl() { 
    local domain=$(cat /root/domain 2>/dev/null || cat /etc/xray/domain) 
     
    print_install "Installing SSL Certificate" 
     
    # Stop web servers 
    systemctl stop nginx 2>/dev/null || true 
     
    # Install acme.sh 
    rm -rf /root/.acme.sh 
    curl https://acme-install.netlify.app/acme.sh | bash 
    source /root/.acme.sh/acme.sh.env 
     
    # Issue certificate 
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt 
    /root/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256 
    /root/.acme.sh/acme.sh --installcert -d $domain \ 
        --fullchainpath /etc/xray/xray.crt \ 
        --keypath /etc/xray/xray.key \ 
        --ecc 
     
    chmod 644 /etc/xray/xray.{crt,key} 
    print_success "SSL Certificate" 
} 
 
install_xray() { 
    print_install "Installing Xray Core (Latest)" 
     
    # Install latest Xray 
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --version latest -u www-data 
     
    # Download configs 
    wget -O /etc/xray/config.json "${REPO}config/config.json" 
    wget -O /etc/nginx/nginx.conf "${REPO}config/nginx.conf" 
    wget -O /etc/nginx/conf.d/xray.conf "${REPO}config/xray.conf" 
    wget -O /etc/haproxy/haproxy.cfg "${REPO}config/haproxy.cfg" 
     
    # Replace domain 
    local domain=$(cat /etc/xray/domain) 
    sed -i "s/xxx/$domain/g" /etc/{haproxy/haproxy.cfg,nginx/conf.d/xray.conf} 
     
    # HAProxy SSL 
    cat /etc/xray/xray.crt /etc/xray/xray.key > /etc/haproxy/hap.pem 
     
    # Xray service 
    cat > /etc/systemd/system/xray.service << 'EOF' 
[Unit] 
Description=Xray Service 
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
 
    systemctl daemon-reload 
    systemctl enable xray nginx haproxy 
    print_success "Xray Core" 
} 
 
install_services() { 
    print_install "Installing additional services" 
     
    # UDP Mini (fixed) 
    mkdir -p /usr/local/kyt 
    wget -q -O /usr/local/kyt/udp-mini "${REPO}files/udp-mini" 
    chmod +x /usr/local/kyt/udp-mini 
     
    # FV Tunnel 
    wget -q https://raw.githubusercontent.com/Jpstore1/jp/main/config/fv-tunnel && \ 
    chmod +x fv-tunnel && ./fv-tunnel 
     
    print_success "Additional services" 
} 
 
finalize_install() { 
    print_install "Finalizing installation" 
     
    # Restart services 
    systemctl restart xray nginx haproxy 
     
    # Show completion time 
    end=$(date +%s) 
    echo -e "${Green}========================================${FONT}" 
    echo -e "${YELLOW} ✓ Installation selesai! ${FONT}" 
    secs_to_human $((end-start)) 
    echo -e "${Green}========================================${FONT}" 
     
    echo -e "${YELLOW}Domain:${FONT} $(cat /etc/xray/domain)" 
    echo -e "${YELLOW}IP:${FONT} $IP" 
} 
 
# ========================================== 
# Main execution 
# ========================================== 
main() { 
    is_root 
    show_banner 
    get_os_info 
    check_system 
     
    read -p $'Press \e[32mEnter\e[0m to continue...' 
     
    install_base_packages 
    setup_system 
    setup_directories 
    setup_domain 
    install_ssl 
    install_xray 
    install_services 
    finalize_install 
     
    echo -e "${Green}Script selesai! Silakan restart VPS.${FONT}" 
} 
 
# Run main function 
main "$@" 

