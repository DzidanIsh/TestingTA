#!/bin/bash

# Warna untuk Terminal
Color_Off='\033[0m'
Yellow='\033[0;33m'
Green='\033[0;32m'
Red='\033[0;31m'
Blue='\033[0;34m'

echo -e "${Yellow}---------------------------------------${Color_Off}"
echo -e "${Yellow}***       Instalasi Wazuh       ***${Color_Off}"
echo -e "${Yellow}***      Untuk Single Node      ***${Color_Off}"
echo -e "${Yellow}---------------------------------------${Color_Off}"

# Cek apakah script dijalankan sebagai root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${Red}Script ini harus dijalankan sebagai root${Color_Off}"
    exit 1
fi

# Fungsi untuk validasi IP address
validate_ip() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        IFS='.' read -r -a ip_parts <<< "$ip"
        for part in "${ip_parts[@]}"; do
            if [ "$part" -lt 0 ] || [ "$part" -gt 255 ]; then
                return 1
            fi
        done
        return 0
    else
        return 1
    fi
}

# Fungsi untuk mendapatkan interface utama
get_main_interface() {
    # Mendapatkan interface default yang terhubung ke internet
    local main_interface=$(ip route | grep default | awk '{print $5}' | head -n1)
    if [ -z "$main_interface" ]; then
        # Fallback: mengambil interface pertama yang aktif (bukan lo)
        main_interface=$(ip -o link show | awk -F': ' '$2 != "lo" {print $2}' | head -n1)
    fi
    echo "$main_interface"
}

# Fungsi untuk mendapatkan gateway
get_default_gateway() {
    local gateway=$(ip route | grep default | awk '{print $3}' | head -n1)
    echo "$gateway"
}

# Fungsi untuk mendapatkan IP yang tersedia
get_available_ip() {
    local interface=$1
    local gateway=$2
    
    # Mendapatkan network prefix dari gateway
    local network_prefix=$(echo "$gateway" | cut -d. -f1-3)
    
    # Mencoba beberapa IP dalam range yang sama dengan gateway
    for i in {10..20}; do
        local test_ip="${network_prefix}.$i"
        if ! ping -c1 -W1 "$test_ip" &>/dev/null; then
            echo "$test_ip"
            return 0
        fi
    done
    
    # Fallback ke IP default jika tidak ada yang tersedia
    echo "${network_prefix}.10"
}

# Fungsi untuk konfigurasi IP Statis
configure_static_ip() {
    local ip=$1
    local interface=$2
    local netmask=$3
    local gateway=$4
    local dns1=$5
    local dns2=$6

    # Buat direktori netplan jika belum ada
    mkdir -p /etc/netplan

    # Backup file konfigurasi network yang ada
    if [ -f "/etc/netplan/00-installer-config.yaml" ]; then
        cp /etc/netplan/00-installer-config.yaml /etc/netplan/00-installer-config.yaml.backup
    fi

    # Buat konfigurasi netplan baru dengan format yang benar
    cat > /etc/netplan/00-installer-config.yaml << EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    ${interface}:
      dhcp4: false
      addresses:
        - ${ip}/${netmask}
      routes:
        - to: default
          via: ${gateway}
      nameservers:
        addresses: [${dns1}, ${dns2}]
EOF

    # Set permission yang benar
    chown root:root /etc/netplan/00-installer-config.yaml
    chmod 0600 /etc/netplan/00-installer-config.yaml

    # Generate dan terapkan konfigurasi
    netplan generate

    # Terapkan konfigurasi dengan penanganan error
    if ! netplan apply; then
        echo -e "${Yellow}Mencoba menerapkan konfigurasi dalam mode debug...${Color_Off}"
        netplan --debug apply
    fi

    # Tunggu sebentar untuk interface up
    sleep 5

    # Verifikasi koneksi
    if ping -c 1 ${gateway} > /dev/null 2>&1; then
        echo -e "${Green}Konfigurasi IP statis berhasil diterapkan${Color_Off}"
        return 0
    else
        echo -e "${Red}Gagal menerapkan konfigurasi IP statis${Color_Off}"
        if [ -f "/etc/netplan/00-installer-config.yaml.backup" ]; then
            mv /etc/netplan/00-installer-config.yaml.backup /etc/netplan/00-installer-config.yaml
            chmod 0600 /etc/netplan/00-installer-config.yaml
            netplan apply
        fi
        return 1
    fi
}

# Fungsi untuk memeriksa dan menginstal dependensi
check_and_install_dependencies() {
    echo -e "${Blue}Memeriksa dan menginstal dependensi...${Color_Off}"
    
    # Update package list
    apt-get update
    
    # Install dependensi yang diperlukan
    apt-get install -y curl apt-transport-https lsb-release gnupg2 net-tools
    
    # Periksa jika instalasi berhasil
    if [ $? -ne 0 ]; then
        echo -e "${Red}Gagal menginstal dependensi${Color_Off}"
        exit 1
    fi
}

# Fungsi untuk memeriksa persyaratan sistem
check_system_requirements() {
    echo -e "${Blue}Memeriksa persyaratan sistem...${Color_Off}"
    
    # Periksa RAM
    total_ram=$(free -m | awk '/^Mem:/{print $2}')
    if [ $total_ram -lt 4096 ]; then
        echo -e "${Red}WARNING: RAM kurang dari 4GB. Wazuh membutuhkan minimal 4GB RAM${Color_Off}"
        read -p "Lanjutkan instalasi? (y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    # Periksa disk space
    free_space=$(df -m / | awk 'NR==2 {print $4}')
    if [ $free_space -lt 10240 ]; then
        echo -e "${Red}WARNING: Ruang disk kurang dari 20GB. Wazuh membutuhkan minimal 20GB free space${Color_Off}"
        read -p "Lanjutkan instalasi? (y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Deteksi otomatis konfigurasi jaringan
echo -e "${Blue}Mendeteksi konfigurasi jaringan...${Color_Off}"

# Deteksi interface utama
INTERFACE=$(get_main_interface)
echo -e "${Green}Interface terdeteksi: $INTERFACE${Color_Off}"

# Deteksi gateway
GATEWAY=$(get_default_gateway)
if [ -z "$GATEWAY" ]; then
    echo -e "${Red}Tidak dapat mendeteksi gateway. Menggunakan default gateway${Color_Off}"
    GATEWAY="192.168.1.1"
fi
echo -e "${Green}Gateway terdeteksi: $GATEWAY${Color_Off}"

# Set IP statis yang tersedia
STATIC_IP=$(get_available_ip "$INTERFACE" "$GATEWAY")
echo -e "${Green}IP statis yang akan digunakan: $STATIC_IP${Color_Off}"

# Set konfigurasi default
NETMASK="24"
DNS1="8.8.8.8"
DNS2="8.8.4.4"

# Periksa persyaratan sistem
check_system_requirements

# Install dependensi
check_and_install_dependencies

# Terapkan konfigurasi IP statis
echo -e "${Yellow}Menerapkan konfigurasi IP statis...${Color_Off}"
configure_static_ip "$STATIC_IP" "$INTERFACE" "$NETMASK" "$GATEWAY" "$DNS1" "$DNS2"

# Buat direktori untuk menyimpan file instalasi
INSTALL_DIR="/root/wazuh-install-files"
mkdir -p ${INSTALL_DIR}
cd ${INSTALL_DIR}

# Download Wazuh installer
echo -e "${Yellow}Mengunduh Wazuh installer...${Color_Off}"
if ! curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh; then
    echo -e "${Red}Gagal mengunduh installer Wazuh${Color_Off}"
    exit 1
fi

chmod +x wazuh-install.sh

# Membuat config.yml
cat > config.yml << EOF
nodes:
  indexer:
    - name: node-1
      ip: ${STATIC_IP}
      role: master
  server:
    - name: wazuh-1
      ip: ${STATIC_IP}
  dashboard:
    - name: dashboard
      ip: ${STATIC_IP}
EOF

# Fungsi untuk menangani error
handle_error() {
    echo -e "${Red}Error: $1${Color_Off}"
    # Simpan log error
    echo "$(date): $1" >> ${INSTALL_DIR}/error.log
    exit 1
}

# Buat direktori untuk menyimpan kredensial
CRED_DIR="/root/wazuh-credentials"
mkdir -p ${CRED_DIR}
chmod 700 ${CRED_DIR}

# Menjalankan instalasi dengan penanganan error
echo -e "${Green}Memulai instalasi Wazuh...${Color_Off}"

# Generate config files
if ! ./wazuh-install.sh --generate-config-files; then
    handle_error "Gagal generate config files"
fi
echo -e "${Green}Konfigurasi berhasil di-generate${Color_Off}"

# Install dan start Wazuh indexer
if ! ./wazuh-install.sh --wazuh-indexer node-1; then
    handle_error "Gagal instalasi wazuh indexer"
fi
echo -e "${Green}Wazuh indexer berhasil diinstal${Color_Off}"

# Tunggu indexer siap
echo -e "${Yellow}Menunggu Wazuh indexer siap...${Color_Off}"
sleep 30

# Start cluster
if ! ./wazuh-install.sh --start-cluster; then
    handle_error "Gagal memulai cluster"
fi
echo -e "${Green}Cluster berhasil dimulai${Color_Off}"

# Simpan password
echo -e "${Yellow}Menyimpan kredensial...${Color_Off}"
tar -axf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt -O > ${CRED_DIR}/wazuh-passwords-full.txt
chmod 600 ${CRED_DIR}/wazuh-passwords-full.txt

# Install Wazuh server
if ! ./wazuh-install.sh --wazuh-server wazuh-1; then
    handle_error "Gagal instalasi wazuh server"
fi
echo -e "${Green}Wazuh server berhasil diinstal${Color_Off}"

# Tunggu server siap
echo -e "${Yellow}Menunggu Wazuh server siap...${Color_Off}"
sleep 30

# Install Wazuh dashboard
if ! ./wazuh-install.sh --wazuh-dashboard dashboard; then
    handle_error "Gagal instalasi wazuh dashboard"
fi
echo -e "${Green}Wazuh dashboard berhasil diinstal${Color_Off}"

# Ekstrak dan simpan password spesifik
cat ${CRED_DIR}/wazuh-passwords-full.txt | grep -A 1 "admin" > ${CRED_DIR}/admin-passwords.txt
cat ${CRED_DIR}/wazuh-passwords-full.txt | grep -A 1 "wazuh" > ${CRED_DIR}/wazuh-passwords.txt
cat ${CRED_DIR}/wazuh-passwords-full.txt | grep -A 1 "kibana" > ${CRED_DIR}/kibana-passwords.txt

# Buat file rangkuman kredensial
cat > ${CRED_DIR}/credentials-summary.txt << EOF
Wazuh Credentials Summary
========================
Tanggal Instalasi: $(date)
IP Server: ${STATIC_IP}

Lokasi File Kredensial:
- Password Lengkap: ${CRED_DIR}/wazuh-passwords-full.txt
- Password Admin: ${CRED_DIR}/admin-passwords.txt
- Password Wazuh: ${CRED_DIR}/wazuh-passwords.txt
- Password Kibana: ${CRED_DIR}/kibana-passwords.txt

Akses Dashboard: https://${STATIC_IP}
Default username: admin

Note: 
- Simpan file ini di tempat yang aman
- Ganti password default setelah login pertama
- Backup folder ${CRED_DIR} secara berkala
EOF

# Set permission untuk file kredensial
chmod 600 ${CRED_DIR}/*
chown -R root:root ${CRED_DIR}

# Tambahkan entri ke /etc/hosts
echo "${STATIC_IP} node-1 wazuh-1 dashboard" >> /etc/hosts

# Periksa status layanan
echo -e "${Yellow}Memeriksa status layanan...${Color_Off}"
services=("wazuh-indexer" "wazuh-manager" "wazuh-dashboard")
for service in "${services[@]}"; do
    if systemctl is-active --quiet $service; then
        echo -e "${Green}Service $service berjalan dengan baik${Color_Off}"
    else
        echo -e "${Red}Service $service tidak berjalan${Color_Off}"
        systemctl status $service
        echo -e "${Yellow}Mencoba restart service ${service}...${Color_Off}"
        systemctl restart $service
        sleep 5
        if systemctl is-active --quiet $service; then
            echo -e "${Green}Service $service berhasil direstart${Color_Off}"
        else
            echo -e "${Red}Service $service masih bermasalah${Color_Off}"
        fi
    fi
done

# Simpan informasi konfigurasi
cat > /root/wazuh-info.txt << EOF
Konfigurasi Wazuh:
=================
IP Address: ${STATIC_IP}
Interface: ${INTERFACE}
Netmask: ${NETMASK}
Gateway: ${GATEWAY}
DNS1: ${DNS1}
DNS2: ${DNS2}

Dashboard URL: https://${STATIC_IP}

Lokasi File Kredensial: ${CRED_DIR}
EOF

echo -e "${Green}Instalasi Wazuh selesai!${Color_Off}"
echo -e "${Yellow}Anda dapat mengakses dashboard di: https://${STATIC_IP}${Color_Off}"
echo -e "${Yellow}Kredensial tersimpan di: ${CRED_DIR}${Color_Off}"
echo -e "${Yellow}Informasi konfigurasi tersimpan di: /root/wazuh-info.txt${Color_Off}"

# Fungsi untuk generate perintah instalasi agent
generate_agent_command() {
    local server_ip=$1
    local WAZUH_VERSION="4.7.5"
    local ARCHITECTURE="amd64"

    echo -e "${Yellow}=== Generator Perintah Instalasi Wazuh Agent ===${Color_Off}"
    echo -e "\n${Yellow}IP Server Wazuh: ${Green}$server_ip${Color_Off}"

    # Input nama agent
    echo -e "\n${Yellow}Masukkan nomor atau nama untuk agent (default: ubuntu-agent):${Color_Off}"
    read agent_name
    if [ -z "$agent_name" ]; then
        agent_name="ubuntu-agent"
    fi

    # Generate perintah instalasi
    local install_command="wget https://packages.wazuh.com/${WAZUH_VERSION%.*}/apt/pool/main/w/wazuh-agent/wazuh-agent_${WAZUH_VERSION}-1_${ARCHITECTURE}.deb && sudo WAZUH_MANAGER='${server_ip}' WAZUH_AGENT_GROUP='default' WAZUH_AGENT_NAME='${agent_name}' dpkg -i ./wazuh-agent_${WAZUH_VERSION}-1_${ARCHITECTURE}.deb"

    # Simpan perintah ke file
    echo "#!/bin/bash" > /root/install_wazuh_agent.sh
    echo "" >> /root/install_wazuh_agent.sh
    echo "# Script instalasi Wazuh Agent" >> /root/install_wazuh_agent.sh
    echo "# Generated pada: $(date)" >> /root/install_wazuh_agent.sh
    echo "# Server: $server_ip" >> /root/install_wazuh_agent.sh
    echo "# Agent Name: $agent_name" >> /root/install_wazuh_agent.sh
    echo "" >> /root/install_wazuh_agent.sh
    echo "$install_command" >> /root/install_wazuh_agent.sh
    echo "" >> /root/install_wazuh_agent.sh
    echo "# Start Wazuh Agent service" >> /root/install_wazuh_agent.sh
    echo "sudo systemctl daemon-reload" >> /root/install_wazuh_agent.sh
    echo "sudo systemctl enable wazuh-agent" >> /root/install_wazuh_agent.sh
    echo "sudo systemctl start wazuh-agent" >> /root/install_wazuh_agent.sh
    echo "" >> /root/install_wazuh_agent.sh
    echo "# Check status" >> /root/install_wazuh_agent.sh
    echo "sudo systemctl status wazuh-agent" >> /root/install_wazuh_agent.sh

    chmod +x /root/install_wazuh_agent.sh

    echo -e "\n${Green}Script instalasi agent telah dibuat: /root/install_wazuh_agent.sh${Color_Off}"
    echo -e "\n${Yellow}Perintah instalasi untuk agent:${Color_Off}"
    echo -e "${Red}$install_command${Color_Off}"
    echo -e "\n${Yellow}Atau gunakan script yang telah dibuat:${Color_Off}"
    echo -e "${Green}scp /root/install_wazuh_agent.sh user@agent-ip:~/${Color_Off}"
    echo -e "${Green}ssh user@agent-ip 'sudo bash ~/install_wazuh_agent.sh'${Color_Off}"

    # Tampilkan ringkasan
    echo -e "\n${Yellow}Ringkasan Agent Installation:${Color_Off}"
    echo -e "1. Server IP: ${Green}$server_ip${Color_Off}"
    echo -e "2. Agent Name: ${Green}$agent_name${Color_Off}"
    echo -e "3. Wazuh Version: ${Green}$WAZUH_VERSION${Color_Off}"
    echo -e "4. Architecture: ${Green}$ARCHITECTURE${Color_Off}"
    echo -e "5. Agent Group: ${Green}default${Color_Off}"

    echo -e "\n${Yellow}Script ini akan menginstal Wazuh Agent versi $WAZUH_VERSION untuk Ubuntu ${ARCHITECTURE}${Color_Off}"
}

# Generate script instalasi agent
echo -e "\n${Yellow}Membuat script instalasi untuk Wazuh Agent...${Color_Off}"
generate_agent_command "${STATIC_IP}"

echo -e "\n${Green}Proses instalasi dan konfigurasi selesai!${Color_Off}"
