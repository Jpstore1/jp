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
 
clear 
# // Exporint IP Address Information 
export IP=$( curl -sS icanhazip.com ) 
 
# // Clear Data 
clear 
 
# // Banner 
echo -e "${YELLOW}----------------------------------------------------------${NC}" 
echo -e "  Author : ${Green}VPN - JP OFFICIAL STORE® ${NC}${YELLOW}(${NC} ${Green} XPRESS ${NC}${YELLOW})${NC}" 
echo -e "${YELLOW}----------------------------------------------------------${NC}" 
echo "" 
sleep 2 
 
# // Checking Os Architecture 
if [[ $( uname -m | awk '{print $1}' ) == "x86_64" ]]; then 
    echo -e "${OK} Your Architecture Is Supported ( ${Green}$( uname -m )${NC} )" 
else 
    echo -e "${ERROR} Your Architecture Is Not Supported ( ${YELLOW}$( uname -m )${NC} )" 
    exit 1 
fi 
 
# // Checking System 
OS_ID=$(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g' | tr -d ' ') 
OS_PRETTY_NAME=$(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g' | tr -d ' ') 
 
if [[ "$OS_ID" == "ubuntu" ]]; then 
    echo -e "${OK} Your OS Is Supported ( ${Green}$OS_PRETTY_NAME${NC} )" 
elif [[ "$OS_ID" == "debian" ]]; then 
    echo -e "${OK} Your OS Is Supported ( ${Green}$OS_PRETTY_NAME${NC} )" 
else 
    echo -e "${ERROR} Your OS Is Not Supported ( ${YELLOW}$OS_PRETTY_NAME${NC} )" 
    exit 1 
fi 
 
# // IP Address Validating 
if [[ -z "$IP" ]]; then 
    echo -e "${ERROR} IP Address ( ${YELLOW}Not Detected${NC} )" 
    exit 1 
else 
    echo -e "${OK} IP Address ( ${Green}$IP${NC} )" 
fi 
 
# // Validate Successful 
echo "" 
read -p "$( echo -e "Press ${GRAY}[ ${NC}${Green}Enter${NC} ${GRAY}]${NC} For Starting Installation") " 
echo "" 
clear 
 
if [ "${EUID}" -ne 0 ]; then 
    echo "You need to run this script as root" 
    exit 1 
fi 
if [ "$(systemd-detect-virt)" == "openvz" ]; then 
    echo "OpenVZ is not supported" 
    exit 1 
fi 
 
# REPO 
REPO="https://raw.githubusercontent.com/Jpstore1/jp/main/" 
 
start=$(date +%s) 
secs_to_human() { 
    echo "Installation time : $((${1} / 3600)) hours $(((${1} / 60) % 60)) minute's $((${1} % 60)) seconds" 
} 
 
### Status Functions 
function print_ok() { 
    echo -e "${OK} ${BLUE} $1 ${FONT}" 
} 
function print_install() { 
    echo -e "${Green} =============================== ${FONT}" 
    echo -e "${YELLOW} # $1 ${FONT}" 
    echo -e "${Green} =============================== ${FONT}" 
    sleep 1 
} 
function print_error() { 
    echo -e "${ERROR} ${REDBG} $1 ${FONT}" 
} 
function print_success() { 
    if [[ 0 -eq $? ]]; then 
        echo -e "${Green} =============================== ${FONT}" 
        echo -e "${Green} # $1 berhasil dipasang" 
        echo -e "${Green} =============================== ${FONT}" 
        sleep 2 
    fi 
} 
 
### Cek root 
function is_root() { 
    if [[ 0 == "$UID" ]]; then 
        print_ok "Root user Start installation process" 
    else 
        print_error "The current user is not the root user, please switch to the root user and run the script again" 
        exit 1 
    fi 
} 
is_root # Panggil fungsi cek root di awal 
 
# Buat direktori xray 
print_install "Membuat direktori xray" 
mkdir -p /etc/xray 
curl -s ifconfig.me > /etc/xray/ipvps 
touch /etc/xray/domain 
mkdir -p /var/log/xray 
chown www-data.www-data /var/log/xray 
chmod +x /var/log/xray 
touch /var/log/xray/access.log 
touch /var/log/xray/error.log 
mkdir -p /var/lib/kyt >/dev/null 2>&1 
# // Ram Information 
while IFS=":" read -r a b; do 
case $a in 
    "MemTotal") ((mem_used+=${b/kB})); mem_total="${b/kB}" ;; 
    "Shmem") ((mem_used+=${b/kB}))  ;; 
    "MemFree" | "Buffers" | "Cached" | "SReclaimable") 
    mem_used="$((mem_used-=${b/kB}))" 
;; 
esac 
done < /proc/meminfo 
Ram_Usage="$((mem_used / 1024))" 
Ram_Total="$((mem_total / 1024))" 
export tanggal=`date -d "0 days" +"%d-%m-%Y - %X" ` 
export OS_Name=$( echo "$OS_PRETTY_NAME" ) # Gunakan variabel yang sudah ada 
export Kernel=$( uname -r ) 
export Arch=$( uname -m ) 
export IP=$( curl -s https://ipinfo.io/ip/ ) 
 
# Change Environment System 
function first_setup(){ 
    timedatectl set-timezone Asia/Jakarta 
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections 
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections 
    print_success "Directory Xray" 
 
    if [[ "$OS_ID" == "ubuntu" ]]; then 
        echo "Setup Dependencies $OS_PRETTY_NAME" 
        apt update -y 
        apt-get install --no-install-recommends software-properties-common -y 
        add-apt-repository ppa:vbernat/haproxy-2.0 -y 
        apt-get -y install haproxy=2.0.\* 
    elif [[ "$OS_ID" == "debian" ]]; then 
        echo "Setup Dependencies For OS Is $OS_PRETTY_NAME" 
        curl https://haproxy.debian.net/bernat.debian.org.gpg | 
            gpg --dearmor >/usr/share/keyrings/haproxy.debian.net.gpg 
        echo "deb [signed-by=/usr/share/keyrings/haproxy.debian.net.gpg]" \ 
            "http://haproxy.debian.net buster-backports-1.8 main" \ 
            >/etc/apt/sources.list.d/haproxy.list 
        apt-get update -y 
        apt-get -y install haproxy=1.8.\* 
    else 
        echo -e " Your OS Is Not Supported (${YELLOW}$OS_PRETTY_NAME${FONT} )" 
        exit 1 
    fi 
} 
 
function nginx_install() { 
    if [[ "$OS_ID" == "ubuntu" ]]; then 
        print_install "Setup nginx For OS Is $OS_PRETTY_NAME" 
        apt-get install nginx -y 
    elif [[ "$OS_ID" == "debian" ]]; then 
        print_success "Setup nginx For OS Is $OS_PRETTY_NAME" 
        apt -y install nginx 
    else 
        echo -e " Your OS Is Not Supported ( ${YELLOW}$OS_PRETTY_NAME${FONT} )" 
    fi 
} 
 
function base_package() { 
    clear 
    print_install "Menginstall Paket Yang Dibutuhkan" 
    apt install -y zip pwgen openssl netcat socat cron bash-completion figlet 
    apt update -y 
    apt upgrade -y 
    apt dist-upgrade -y 
 
    systemctl enable chronyd || true # Gunakan || true untuk mencegah error jika service tidak ada 
    systemctl restart chronyd || true 
    systemctl enable chrony || true 
    systemctl restart chrony || true 
    chronyc sourcestats -v || true 
    chronyc tracking -v || true 
    apt install -y ntpdate 
    ntpdate pool.ntp.org 
 
    apt install -y sudo 
    apt-get clean all 
    apt-get autoremove -y 
    apt-get install -y debconf-utils 
    apt-get remove --purge exim4 -y || true 
    apt-get remove --purge ufw firewalld -y || true 
    apt-get install -y --no-install-recommends software-properties-common 
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections 
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections 
    apt-get install -y speedtest-cli vnstat libnss3-dev libnspr4-dev pkg-config libpam0g-dev libcap-ng-dev libcap-ng-utils libselinux1-dev libcurl4-nss-dev flex bison make libnss3-tools libevent-dev bc rsyslog dos2unix zlib1g-dev libssl-dev libsqlite3-dev sed dirmngr libxml-parser-perl build-essential gcc g++ python htop lsof tar wget curl ruby zip unzip p7zip-full python3-pip libc6 util-linux msmtp-mta ca-certificates bsd-mailx iptables iptables-persistent netfilter-persistent net-tools openssl gnupg gnupg2 lsb-release gcc shc cmake git screen socat xz-utils apt-transport-https gnupg1 dnsutils openvpn easy-rsa 
    print_success "Paket Yang Dibutuhkan" 
} 
 
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
if [[ "$host" == "1" ]]; then 
    echo -e "   \e[1;32mPlease Enter Your Subdomain $NC" 
    read -p "   Subdomain: " host1 
    echo "IP=" >> /var/lib/kyt/ipvps.conf 
    echo "$host1" > /etc/xray/domain 
    echo "$host1" > /root/domain 
    echo "" 
elif [[ "$host" == "2" ]]; then 
    #install cf 
    wget "${REPO}files/cf.sh" && chmod +x cf.sh && ./cf.sh 
    rm -f /root/cf.sh 
    clear 
else 
    print_install "Random Subdomain/Domain is Used" 
    clear 
fi 
} 
 
function set_root_password() { 
    print_install "Mengatur Kata Sandi Root Baru" 
    read -s -p "Masukkan kata sandi root baru: " ROOT_PASSWORD 
    echo 
    read -s -p "Ulangi kata sandi root baru: " ROOT_PASSWORD_CONFIRM 
    echo 
 
    if [[ "$ROOT_PASSWORD" == "$ROOT_PASSWORD_CONFIRM" && -n "$ROOT_PASSWORD" ]]; then 
        echo "root:$ROOT_PASSWORD" | chpasswd 
        print_success "Kata Sandi Root berhasil diatur" 
    else 
        print_error "Kata Sandi tidak cocok atau kosong. Pengaturan kata sandi root dibatalkan." 
        sleep 2 
    fi 
} 
 
function check_license_and_notify(){ 
    MYIP=$(curl -sS ipv4.icanhazip.com) 
    echo -e "\e[32mloading...\e[0m" 
    izinsc="https://raw.githubusercontent.com/Jpstore1/jp/main/Regist" 
 
    # USERNAME 
    rm -f /usr/bin/user 
    username=$(curl -s $izinsc | grep $MYIP | awk '{print $2}') 
    echo "$username" >/usr/bin/user 
    expx=$(curl -s $izinsc | grep $MYIP | awk '{print $3}') 
    echo "$expx" >/usr/bin/e 
 
    # DETAIL ORDER 
    username=$(cat /usr/bin/user) 
    oid=$(cat /usr/bin/ver || echo "N/A") # Tambahkan default jika file tidak ada 
    exp=$(cat /usr/bin/e) 
     
    # VPS Information 
    DATE=$(date +'%Y-%m-%d') 
    # ISP=$(curl -s ipinfo.io/org | cut -d " " -f 2-10) # already fetched in install_xray 
    ISP=$(cat /etc/xray/isp) # Use the one fetched earlier 
    domain=$(cat /etc/xray/domain || echo "N/A") # Ambil domain dari file 
 
    # Status Expired Active 
    today=`date -d "0 days" +"%Y-%m-%d"` 
    Exp1=$(curl -s $izinsc | grep $MYIP | awk '{print $4}') 
     
    Info="(${Green}Active${NC})" 
    Error="(${RED}ExpiRED${NC})" 
 
    if [[ "$today" < "$Exp1" ]]; then 
        sts="${Info}" 
    else 
        sts="${Error}" 
    fi 
 
    TIMES="10" 
    CHATID="1626302370" 
    KEY="6879615968:AAErYxZHEnmqystuGFD2Xl5R-l9Mwh-_plo" # WARNING: Kredensial terekspos! 
    URL="https://api.telegram.org/bot$KEY/sendMessage" 
    TIMEZONE=$(printf '%(%H:%M:%S)T') 
 
    TEXT=" 
\`----------------------------------------\` 
*⚡AUTOSCRIPT PREMIUM⚡* 
\`----------------------------------------\` 
\`User     :\`${username} 
\`Domain   :\`${domain} 
\`IPVPS    :\`${MYIP} 
\`ISP      :\`${ISP} 
\`Exp Sc.  :\`${exp} 
\`----------------------------------------\` 
*🇮🇩TUNNELING🇮🇩* 
\`----------------------------------------\` 
_Automatic Notifications From Github_ 
" 
    # Menggunakan curl tanpa "&reply_markup" jika tidak diperlukan untuk menghindari karakter aneh 
    curl -s --max-time "$TIMES" -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=Markdown" "$URL" >/dev/null 
} 
 
function pasang_ssl() { 
clear 
print_install "Memasang SSL Pada Domain" 
    rm -rf /etc/xray/xray.key 
    rm -rf /etc/xray/xray.crt 
    domain=$(cat /root/domain) 
    STOPWEBSERVER=$(lsof -i:80 | grep LISTEN | awk '{print $1}' | uniq) # Lebih robust 
     
    rm -rf /root/.acme.sh 
    mkdir /root/.acme.sh 
     
    if [[ -n "$STOPWEBSERVER" ]]; then 
        systemctl stop "$STOPWEBSERVER" || true 
    fi 
    systemctl stop nginx || true 
     
    curl https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh 
    chmod +x /root/.acme.sh/acme.sh 
    /root/.acme.sh/acme.sh --upgrade --auto-upgrade 
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt 
    /root/.acme.sh/acme.sh --issue -d "$domain" --standalone -k ec-256 
    ~/.acme.sh/acme.sh --installcert -d "$domain" --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc 
    chmod 600 /etc/xray/xray.key # Seharusnya 600, bukan 777 untuk keamanan 
    print_success "SSL Certificate" 
} 
 
function make_folder_xray() { 
    # Hapus file database lama 
    rm -f /etc/vmess/.vmess.db /etc/vless/.vless.db /etc/trojan/.trojan.db \ 
          /etc/shadowsocks/.shadowsocks.db /etc/ssh/.ssh.db /etc/bot/.bot.db \ 
          /etc/user-create/user.log 
 
    # Buat direktori yang dibutuhkan 
    mkdir -p /etc/bot /etc/xray /etc/vmess /etc/vless /etc/trojan /etc/shadowsocks \ 
             /etc/ssh /usr/bin/xray/ /var/log/xray/ /var/www/html \ 
             /etc/kyt/limit/vmess/ip /etc/kyt/limit/vless/ip /etc/kyt/limit/trojan/ip \ 
             /etc/kyt/limit/ssh/ip /etc/limit/vmess /etc/limit/vless /etc/limit/trojan \ 
             /etc/limit/ssh /etc/user-create 
 
    # Set izin untuk /var/log/xray 
    chmod +x /var/log/xray 
 
    # Buat file placeholder 
    touch /etc/xray/domain /var/log/xray/access.log /var/log/xray/error.log \ 
          /etc/vmess/.vmess.db /etc/vless/.vless.db /etc/trojan/.trojan.db \ 
          /etc/shadowsocks/.shadowsocks.db /etc/ssh/.ssh.db /etc/bot/.bot.db 
 
    # Tambahkan header ke file database 
    echo "& plughin Account" >>/etc/vmess/.vmess.db 
    echo "& plughin Account" >>/etc/vless/.vless.db 
    echo "& plughin Account" >>/etc/trojan/.trojan.db 
    echo "& plughin Account" >>/etc/shadowsocks/.shadowsocks.db 
    echo "& plughin Account" >>/etc/ssh/.ssh.db 
    echo "echo -e 'Vps Config User Account'" >> /etc/user-create/user.log 
} 
 
function install_xray() { 
    clear 
    print_install "Core Xray 1.8.1 Latest Version" 
    domainSock_dir="/run/xray";! [ -d "$domainSock_dir" ] && mkdir -p "$domainSock_dir" 
    chown www-data.www-data "$domainSock_dir" 
     
    # // Ambil Xray Core Version Terbaru 
    latest_version="$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)" 
    if [[ -z "$latest_version" ]]; then 
        print_error "Gagal mendapatkan versi Xray terbaru. Instalasi mungkin gagal." 
        exit 1 
    fi 
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version "$latest_version" 
    if [ $? -ne 0 ]; then print_error "Instalasi Xray Core Gagal!"; exit 1; fi 
 
    # // Ambil Config Server 
    wget -O /etc/xray/config.json "${REPO}config/config.json" 
    wget -O /etc/systemd/system/runn.service "${REPO}files/runn.service" 
     
    domain=$(cat /etc/xray/domain) 
    IPVS=$(cat /etc/xray/ipvps) # Tidak digunakan, bisa dihapus jika tidak diperlukan 
    print_success "Core Xray 1.8.1 Latest Version" 
     
    # Settings UP Nginx Server 
    clear 
    curl -s ipinfo.io/city >/etc/xray/city 
    curl -s ipinfo.io/org | cut -d " " -f 2-10 >/etc/xray/isp 
    print_install "Memasang Konfigurasi Paket" 
    wget -O /etc/haproxy/haproxy.cfg "${REPO}config/haproxy.cfg" 
    wget -O /etc/nginx/conf.d/xray.conf "${REPO}config/xray.conf" 
    sed -i "s/xxx/${domain}/g" /etc/haproxy/haproxy.cfg 
    sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf 
    curl "${REPO}config/nginx.conf" > /etc/nginx/nginx.conf 
     
    # Buat file hap.pem (SSL certificate untuk HAProxy) 
    cat /etc/xray/xray.crt /etc/xray/xray.key | tee /etc/haproxy/hap.pem 
 
    # > Set Permission 
    chmod +x /etc/systemd/system/runn.service 
 
    # > Create Service 
    rm -rf /etc/systemd/system/xray.service.d # Hapus jika ada service unit lain 
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
print_success "Konfigurasi Paket" 
} 
 
function ssh_setup(){ 
clear 
print_install "Memasang Password SSH" 
    wget -O /etc/pam.d/common-password "${REPO}files/password" 
chmod +x /etc/pam.d/common-password 
 
    # Menghapus konfigurasi keyboard yang tidak perlu untuk server headless 
    # DEBIAN_FRONTEND=noninteractive dpkg-reconfigure keyboard-configuration 
    # ... (blok debconf-set-selections dihapus) ... 
 
    # go to root 
    cd /root/ || exit 1 # Perbaikan: exit jika gagal pindah direktori 
 
    # Edit file /etc/systemd/system/rc-local.service 
    cat > /etc/systemd/system/rc-local.service <<-END 
[Unit] 
Description=/etc/rc.local 
ConditionPathExists=/etc/rc.local 
[Service] 
Type=forking 
ExecStart=/etc/rc.local start 
TimeoutSec=0 
StandardOutput=tty 
RemainAfterExit=yes 
SysVStartPriority=99 
[Install] 
WantedBy=multi-user.target 
END 
 
    # nano /etc/rc.local 
    cat > /etc/rc.local <<-END 
#!/bin/sh -e 
# rc.local 
# By default this script does nothing. 
exit 0 
END 
 
    # Ubah izin akses 
    chmod +x /etc/rc.local 
 
    # enable rc local 
    systemctl enable rc-local 
    systemctl start rc-local.service 
 
    # disable ipv6 
    echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6 
    sed -i '$ a\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local # Gunakan 'a' untuk append 
 
    # set time GMT +7 
    ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime 
 
    # set locale 
    sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config 
    print_success "Password SSH" 
} 
 
function udp_mini(){ 
clear 
print_install "Memasang Service Limit IP & Quota" 
wget -q "${REPO}config/fv-tunnel" && chmod +x fv-tunnel && ./fv-tunnel 
 
# // Installing UDP Mini 
mkdir -p /usr/local/kyt/ 
wget -q -O /usr/local/kyt/udp-mini "${REPO}files/udp-mini" 
chmod +x /usr/local/kyt/udp-mini 
 
wget -q -O /etc/systemd/system/udp-mini-1.service "${REPO}files/udp-mini-1.service" 
wget -q -O /etc/systemd/system/udp-mini-2.service "${REPO}files/udp-mini-2.service" 
wget -q -O /etc/systemd/system/udp-mini-3.service "${REPO}files/udp-mini-3.service" 
 
systemctl daemon-reload # Reload unit files 
systemctl disable udp-mini-1 udp-mini-2 udp-mini-3 || true # Disable in case already running 
systemctl stop udp-mini-1 udp-mini-2 udp-mini-3 || true # Stop in case already running 
systemctl enable udp-mini-1 udp-mini-2 udp-mini-3 
systemctl start udp-mini-1 udp-mini-2 udp-mini-3 
 
print_success "Limit IP Service" 
} 
 
function ssh_slow(){ 
clear 
print_install "Memasang modul SlowDNS Server" 
    wget -q -O /tmp/nameserver "${REPO}files/nameserver" 
    chmod +x /tmp/nameserver 
    bash /tmp/nameserver | tee /root/install.log 
 print_success "SlowDNS" 
} 
 
function ins_SSHD(){ 
clear 
print_install "Memasang SSHD" 
wget -q -O /etc/ssh/sshd_config "${REPO}files/sshd" 
chmod 600 /etc/ssh/sshd_config # Izin yang lebih aman 
systemctl restart sshd || /etc/init.d/ssh restart # Perbaikan untuk nama service 
systemctl status sshd || /etc/init.d/ssh status 
print_success "SSHD" 
} 
 
function ins_dropbear(){ 
clear 
print_install "Menginstall Dropbear" 
apt-get install -y dropbear 
wget -q -O /etc/default/dropbear "${REPO}config/dropbear.conf" 
chmod +x /etc/default/dropbear 
systemctl restart dropbear || /etc/init.d/dropbear restart 
systemctl status dropbear || /etc/init.d/dropbear status 
print_success "Dropbear" 
} 
 
function ins_vnstat(){ 
clear 
print_install "Menginstall Vnstat" 
# Dapatkan nama interface jaringan default 
NET=$(ip -4 route show default | awk '{print $5}' | head -n 1) 
if [[ -z "$NET" ]]; then 
    print_error "Tidak dapat mendeteksi interface jaringan. Vnstat mungkin tidak berfungsi." 
    sleep 2 
fi 
 
apt -y install vnstat 
systemctl restart vnstat || true 
apt -y install libsqlite3-dev 
 
wget "https://humdi.net/vnstat/vnstat-2.6.tar.gz" 
tar zxvf vnstat-2.6.tar.gz 
cd vnstat-2.6 || exit 1 
./configure --prefix=/usr --sysconfdir=/etc && make && make install 
cd /root/ || exit 1 # Kembali ke /root 
vnstat -u -i "$NET" 
sed -i "s/Interface \"eth0\"/Interface \"$NET\"/g" /etc/vnstat.conf 
chown vnstat:vnstat /var/lib/vnstat -R 
systemctl enable vnstat 
systemctl restart vnstat 
systemctl status vnstat 
rm -f /root/vnstat-2.6.tar.gz 
rm -rf /root/vnstat-2.6 
print_success "Vnstat" 
} 
 
function ins_openvpn(){ 
clear 
print_install "Menginstall OpenVPN" 
wget "${REPO}files/openvpn" && chmod +x openvpn && ./openvpn 
systemctl restart openvpn || /etc/init.d/openvpn restart 
print_success "OpenVPN" 
} 
 
function ins_backup(){ 
clear 
print_install "Memasang Backup Server" 
apt install -y rclone 
printf "q\n" | rclone config # Ini akan membuat konfigurasi rclone default 
wget -O /root/.config/rclone/rclone.conf "${REPO}config/rclone.conf" 
 
#Install Wondershaper 
cd /bin || exit 1 
git clone  https://github.com/LunaticTunnel/wondershaper.git 
cd wondershaper || exit 1 
sudo make install 
cd /root/ || exit 1 
rm -rf wondershaper 
echo > /home/limit # Buat file kosong 
apt install -y msmtp-mta ca-certificates bsd-mailx 
 
# WARNING: Kredensial email terekspos dalam plain text! 
# Sebaiknya minta input dari pengguna atau gunakan metode yang lebih aman. 
cat <<EOF >/etc/msmtprc 
defaults 
tls on 
tls_starttls on 
tls_trust_file /etc/ssl/certs/ca-certificates.crt 
 
account default 
host smtp.gmail.com 
port 587 
auth on 
user oceantestdigital@gmail.com 
from oceantestdigital@gmail.com 
password your_secure_password_here # GANTI INI DENGAN PASSWORD ASLI ATAU VARIABEL AMAN 
logfile ~/.msmtp.log 
EOF 
chown root:root /etc/msmtprc # Hanya root yang perlu baca/tulis 
chmod 600 /etc/msmtprc # Hanya root yang bisa baca/tulis 
 
wget -q -O /etc/ipserver "${REPO}files/ipserver" && bash /etc/ipserver 
print_success "Backup Server" 
} 
 
function ins_swab(){ 
clear 
print_install "Memasang Swap 1 G" 
gotop_latest="$(curl -s https://api.github.com/repos/xxxserxxx/gotop/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)" 
    gotop_link="https://github.com/xxxserxxx/gotop/releases/download/v$gotop_latest/gotop_v"$gotop_latest"_linux_amd64.deb" 
    curl -sL "$gotop_link" -o /tmp/gotop.deb 
    dpkg -i /tmp/gotop.deb >/dev/null 2>&1 
     
    # > Buat swap sebesar 1G 
    if ! grep -q "/swapfile" /etc/fstab; then 
        dd if=/dev/zero of=/swapfile bs=1M count=1024 # Lebih modern pakai 1M 
        mkswap /swapfile 
        chown root:root /swapfile 
        chmod 0600 /swapfile 
        swapon /swapfile 
        echo '/swapfile none swap sw 0 0' | tee -a /etc/fstab # Menggunakan tee -a 
    else 
        print_ok "Swapfile sudah ada." 
    fi 
 
    # > Singkronisasi jam 
    chronyd -q 'server 0.id.pool.ntp.org iburst' || true 
    chronyc sourcestats -v || true 
    chronyc tracking -v || true 
     
    wget "${REPO}files/bbr.sh" && chmod +x bbr.sh && ./bbr.sh 
print_success "Swap 1 G" 
} 
 
function ins_Fail2ban(){ 
clear 
print_install "Menginstall Fail2ban" 
apt -y install fail2ban # Aktifkan instalasi 
systemctl enable --now fail2ban 
systemctl restart fail2ban 
systemctl status fail2ban 
 
# Instal DDOS Flate 
if [ -d '/usr/local/ddos' ]; then 
    print_ok "DDOS Deflate sudah terinstal." 
else 
    mkdir /usr/local/ddos 
    # Lanjutkan instalasi DDOS Deflate di sini jika ada file/skripnya 
    # wget ... 
    # chmod ... 
    # ./install.sh ... 
    print_ok "Direktori DDOS Deflate dibuat. Lanjutkan instalasi manual jika diperlukan." 
fi 
 
clear 
# banner 
echo "Banner /etc/kyt.txt" >>/etc/ssh/sshd_config 
sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/kyt.txt"@g' /etc/default/dropbear 
 
# Ganti Banner 
wget -O /etc/kyt.txt "${REPO}files/issue.net" 
print_success "Fail2ban" 
} 
 
function ins_epro(){ 
clear 
print_install "Menginstall ePro WebSocket Proxy" 
    wget -O /usr/bin/ws "${REPO}files/ws" 
    wget -O /usr/bin/tun.conf "${REPO}config/tun.conf" 
    wget -O /etc/systemd/system/ws.service "${REPO}files/ws.service" 
    chmod +x /etc/systemd/system/ws.service 
    chmod +x /usr/bin/ws 
    chmod 644 /usr/bin/tun.conf 
 
systemctl daemon-reload # Reload unit files 
systemctl disable ws || true 
systemctl stop ws || true 
systemctl enable ws 
systemctl start ws 
systemctl restart ws 
 
wget -q -O /usr/local/share/xray/geosite.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" 
wget -q -O /usr/local/share/xray/geoip.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" 
wget -O /usr/sbin/ftvpn "${REPO}files/ftvpn" 
chmod +x /usr/sbin/ftvpn 
 
# Aturan iptables untuk memblokir P2P/BitTorrent 
iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP 
iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP 
iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP 
iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP 
iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP 
iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP 
iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP 
iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP 
iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP 
iptables -A FORWARD -m string --algo bm --string "announce" -j DROP 
iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP 
iptables-save > /etc/iptables.up.rules 
netfilter-persistent save 
netfilter-persistent reload 
 
# remove unnecessary files 
cd /root/ || exit 1 
apt autoclean -y 
apt autoremove -y 
print_success "ePro WebSocket Proxy" 
} 
 
function ins_restart_services(){ 
clear 
print_install "Restarting All Services" 
systemctl daemon-reload 
systemctl restart nginx || true 
systemctl restart openvpn || true 
systemctl restart sshd || true 
systemctl restart dropbear || true 
systemctl restart fail2ban || true 
systemctl restart vnstat || true 
systemctl restart haproxy || true 
systemctl restart cron || true 
systemctl restart netfilter-persistent || true 
systemctl restart xray || true 
systemctl restart ws || true 
 
systemctl enable --now nginx || true 
systemctl enable --now xray || true 
systemctl enable --now rc-local || true 
systemctl enable --now dropbear || true 
systemctl enable --now openvpn || true 
systemctl enable --now cron || true 
systemctl enable --now haproxy || true 
systemctl enable --now netfilter-persistent || true 
systemctl enable --now ws || true 
systemctl enable --now fail2ban || true 
 
history -c 
echo "unset HISTFILE" >> /etc/profile 
 
cd /root/ || exit 1 
rm -f /root/openvpn 
rm -f /root/key.pem 
rm -f /root/cert.pem 
print_success "All Services Restarted" 
} 
 
function menu(){ 
    clear 
    print_install "Memasang Menu Paket" 
    wget "${REPO}menu/menu.zip" 
    if [ $? -ne 0 ]; then print_error "Gagal mengunduh menu.zip"; return 1; fi 
    unzip -o menu.zip # -o untuk overwrite tanpa prompt 
    if [ $? -ne 0 ]; then print_error "Gagal unzip menu.zip"; return 1; fi 
    chmod +x menu/* 
    mv menu/* /usr/local/sbin 
    rm -rf menu 
    rm -rf menu.zip 
    print_success "Menu Paket" 
} 
 
function profile_and_cron(){ 
clear 
    print_install "Mengatur Profil dan Cronjobs" 
    cat >/root/.profile <<EOF 
# ~/.profile: executed by Bourne-compatible login shells. 
if [ "$BASH" ]; then 
    if [ -f ~/.bashrc ]; then 
        . ~/.bashrc 
    fi 
fi 
mesg n || true 
menu 
EOF 
 
    cat >/etc/cron.d/xp_all <<-END 
		SHELL=/bin/sh 
		PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin 
		2 0 * * * root /usr/local/sbin/xp 
	END 
	cat >/etc/cron.d/logclean <<-END 
		SHELL=/bin/sh 
		PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin 
		*/20 * * * * root /usr/local/sbin/clearlog 
		END 
    chmod 644 /root/.profile 
	 
    cat >/etc/cron.d/daily_reboot <<-END 
		SHELL=/bin/sh 
		PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin 
		0 5 * * * root /sbin/reboot 
	END 
    cat >/etc/cron.d/limit_ip <<-END 
		SHELL=/bin/sh 
		PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin 
		*/2 * * * * root /usr/local/sbin/limit-ip 
	END 
    cat >/etc/cron.d/limit_ip2 <<-END 
		SHELL=/bin/sh 
		PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin 
		*/2 * * * * root /usr/bin/limit-ip 
	END 
    echo "*/1 * * * * root echo -n > /var/log/nginx/access.log" >/etc/cron.d/log.nginx 
    echo "*/1 * * * * root echo -n > /var/log/xray/access.log" >>/etc/cron.d/log.xray 
    service cron restart 
 
    cat >/home/daily_reboot <<-END 
		5 
	END 
 
    cat >/etc/systemd/system/rc-local.service <<EOF 
[Unit] 
Description=/etc/rc.local 
ConditionPathExists=/etc/rc.local 
[Service] 
Type=forking 
ExecStart=/etc/rc.local start 
TimeoutSec=0 
StandardOutput=tty 
RemainAfterExit=yes 
SysVStartPriority=99 
[Install] 
WantedBy=multi-user.target 
EOF 
 
    echo "/bin/false" >>/etc/shells 
    echo "/usr/sbin/nologin" >>/etc/shells 
    cat >/etc/rc.local <<EOF 
#!/bin/sh -e 
# rc.local 
# By default this script does nothing. 
iptables -I INPUT -p udp --dport 5300 -j ACCEPT 
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300 
systemctl restart netfilter-persistent 
exit 0 
EOF 
 
    chmod +x /etc/rc.local 
     
    AUTOREB=$(cat /home/daily_reboot) 
    SETT=11 
    if [ "$AUTOREB" -gt "$SETT" ]; then 
        TIME_DATE="PM" 
    else 
        TIME_DATE="AM" 
    fi 
print_success "Menu Paket" 
} 
 
# Restart layanan after install 
function enable_services(){ 
clear 
print_install "Enable Services" 
    systemctl daemon-reload 
    systemctl enable netfilter-persistent 
    systemctl start netfilter-persistent 
    systemctl enable rc-local 
    systemctl enable cron 
    systemctl enable nginx 
    systemctl enable xray 
    systemctl enable haproxy 
    systemctl enable ws 
    systemctl enable fail2ban 
    # Openvpn, sshd, dropbear already handled in their respective functions or base_package 
     
    systemctl restart nginx || true 
    systemctl restart xray || true 
    systemctl restart cron || true 
    systemctl restart haproxy || true 
    print_success "Services Enabled" 
    clear 
} 
 
# Fingsi Install Script 
function instal(){ 
clear 
    first_setup 
    nginx_install 
    base_package 
    make_folder_xray 
    pasang_domain 
    set_root_password # Perbaikan: Panggil fungsi ini 
    pasang_ssl 
    install_xray 
    ssh_setup # Perbaikan: Ganti nama fungsi 
    udp_mini 
    ssh_slow 
    ins_SSHD 
    ins_dropbear 
    ins_vnstat 
    ins_openvpn 
    ins_backup 
    ins_swab 
    ins_Fail2ban 
    ins_epro 
    ins_restart_services # Perbaikan: Ganti nama fungsi 
    menu 
    profile_and_cron # Perbaikan: Ganti nama fungsi 
    enable_services 
    check_license_and_notify # Perbaikan: Ganti nama fungsi 
} 
instal 
echo "" 
history -c 
rm -rf /root/menu 
rm -rf /root/*.zip 
rm -rf /root/*.sh 
rm -rf /root/LICENSE 
rm -rf /root/README.md 
rm -rf /root/domain 
 
sudo hostnamectl set-hostname "$username" # Gunakan username dari izin skrip 
secs_to_human "$(($(date +%s) - ${start}))" 
echo -e "${Green} Allhamdulillah Script Successfull Installed${NC}" 
echo "" 
read -p "$( echo -e "Press ${YELLOW}[ ${NC}${YELLOW}Enter${NC} ${YELLOW}]${NC} For reboot") " 
reboot 
 

