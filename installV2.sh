#!/bin/bash

# Script Instalasi Sistem SOC (Security Operations Center)
# Berdasarkan NIST 800-61 Incident Response Life Cycle Framework
# Components: Wazuh, YARA, ClamAV, Custom Scripts
# ------------------------------------------------------------------------------------
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

# --- PENAMBAHAN LOGGING ---
# Definisikan path file log terpusat
LOG_FILE="/var/log/soc_install.log"
# Inisialisasi file log. Dijalankan sebagai root/sudo, jadi kita punya akses.
# Mengosongkan log lama dan menambahkan header untuk sesi instalasi baru.
echo "===== SOC Installation Log - Dimulai pada $(date '+%Y-%m-%d %H:%M:%S') =====" > "$LOG_FILE"
chmod 640 "$LOG_FILE"

# Fungsi untuk menampilkan pesan error dan keluar
error_exit() {
    echo -e "\e[31m[ERROR] $(date '+%Y-%m-%d %H:%M:%S') - $1\e[0m"
    exit 1
}

# Fungsi untuk menampilkan pesan error dan keluar
error_exit() {
    local msg="$1"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    # Pesan ke layar (stderr) dengan warna
    echo -e "\e[31m[ERROR] $timestamp - $msg\e[0m" >&2
    # Pesan ke file log tanpa warna
    echo "[ERROR] $timestamp - $msg" >> "$LOG_FILE"
    echo "===== Instalasi Gagal pada $timestamp =====" >> "$LOG_FILE"
    exit 1
}

# Fungsi untuk menampilkan pesan sukses
success_msg() {
    local msg="$1"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    # Pesan ke layar dengan warna
    echo -e "\e[32m[SUCCESS] $timestamp - $msg\e[0m"
    # Pesan ke file log tanpa warna
    echo "[SUCCESS] $timestamp - $msg" >> "$LOG_FILE"
}

# Fungsi untuk menampilkan pesan info
info_msg() {
    local msg="$1"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    # Pesan ke layar dengan warna
    echo -e "\e[34m[INFO] $timestamp - $msg\e[0m"
    # Pesan ke file log tanpa warna
    echo "[INFO] $timestamp - $msg" >> "$LOG_FILE"
}

# Fungsi untuk menampilkan pesan peringatan
warning_msg() {
    local msg="$1"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    # Pesan ke layar dengan warna
    echo -e "\e[33m[WARNING] $timestamp - $msg\e[0m"
    # Pesan ke file log tanpa warna
    echo "[WARNING] $timestamp - $msg" >> "$LOG_FILE"
}

# Fungsi untuk memvalidasi IP address
validate_ip() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        IFS='.' read -r -a ip_parts <<< "$ip"
        for part in "${ip_parts[@]}"; do
            if [ "$part" -gt 255 ] || [ "$part" -lt 0 ]; then
                return 1
            fi
        done
        return 0
    fi
    return 1
}

# Fungsi untuk memvalidasi path
validate_path() {
    local path=$1
    if [[ "$path" =~ ^/ ]]; then
        return 0
    fi
    return 1
}

# Mengalihkan stdout dan stderr dari SEMUA perintah berikutnya ke file log,
exec > >(tee -a "$LOG_FILE") 2> >(tee -a "$LOG_FILE" >&2)

# Banner
echo "================================================================="
echo "    INSTALASI SISTEM SOC - NIST 800-61 INCIDENT RESPONSE       "
echo "================================================================="
echo ""

# 1. Verifikasi Sistem dan Dependensi Awal
# ------------------------------------------
info_msg "Memulai verifikasi sistem dan dependensi awal..."

if [ "$(id -u)" -ne 0 ]; then
    error_exit "Script ini harus dijalankan sebagai root atau dengan sudo."
fi

# Periksa distribusi Ubuntu Server 22.04
if ! lsb_release -a 2>/dev/null | grep -q "Ubuntu 22.04"; then
    warning_msg "Sistem ini tidak terdeteksi sebagai Ubuntu 22.04. Proses instalasi akan dilanjutkan namun mungkin ada masalah kompatibilitas."
fi

if ! command -v apt-get &> /dev/null; then
    error_exit "Sistem operasi tidak didukung (hanya Debian/Ubuntu dengan apt-get)."
fi

# Periksa koneksi internet
info_msg "Memeriksa koneksi internet..."
if ! ping -c 1 -W 5 8.8.8.8 &> /dev/null; then
    error_exit "Tidak ada koneksi internet. Pastikan sistem terhubung ke internet."
fi

info_msg "Melakukan update daftar paket (apt-get update)..."
apt-get update -y || warning_msg "Gagal melakukan apt-get update, proses instalasi dilanjutkan."

# Instalasi dependensi dasar dengan versi spesifik
REQUIRED_CMDS=("git" "python3" "curl" "pip3" "rsync" "dos2unix" "wget" "unzip" "ufw" "fail2ban")
for cmd in "${REQUIRED_CMDS[@]}"; do
    if ! command -v "$cmd" &> /dev/null; then
        info_msg "$cmd tidak ditemukan. Mencoba menginstal..."
        if [[ "$cmd" == "pip3" ]]; then
            apt-get install -y python3-pip || error_exit "Gagal menginstal python3-pip."
        elif [[ "$cmd" == "python3" ]]; then
            apt-get install -y python3 python3-venv python3-pip || error_exit "Gagal menginstal python3."
        else
            apt-get install -y "$cmd" || error_exit "Gagal menginstal $cmd."
        fi
        success_msg "$cmd berhasil diinstal."
    else
        info_msg "$cmd sudah terinstal."
    fi
done

# Konfigurasi UFW (Uncomplicated Firewall)
info_msg "Mengkonfigurasi firewall (UFW)..."
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow http
ufw allow https
ufw --force enable || warning_msg "Gagal mengaktifkan UFW."

# Konfigurasi Fail2ban
info_msg "Mengkonfigurasi Fail2ban..."
if [ -f /etc/fail2ban/jail.local ]; then
    cp /etc/fail2ban/jail.local /etc/fail2ban/jail.local.backup.$(date +%Y%m%d_%H%M%S)
fi

cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600

[apache]
enabled = true
port = http,https
filter = apache-auth
logpath = /var/log/apache2/error.log
maxretry = 3
bantime = 3600
EOF

systemctl restart fail2ban || warning_msg "Gagal restart Fail2ban."

# Instalasi Apache2 web server
if ! command -v apache2 &> /dev/null; then
    info_msg "Apache2 tidak ditemukan. Menginstal Apache2..."
    apt-get install -y apache2 || error_exit "Gagal menginstal Apache2."
    systemctl enable apache2
    systemctl start apache2
    success_msg "Apache2 berhasil diinstal dan diaktifkan."
else
    info_msg "Apache2 sudah terinstal."
    systemctl enable apache2 2>/dev/null || true
    systemctl restart apache2 || warning_msg "Gagal restart Apache2."
fi

# 2. Instalasi dan Konfigurasi Wazuh Agent
# -----------------------------------------
info_msg "Memulai instalasi dan konfigurasi Wazuh Agent..."

# Tambahkan GPG key dan repository Wazuh
if [ ! -f /usr/share/keyrings/wazuh.gpg ]; then
    info_msg "Menambahkan GPG key Wazuh..."
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
    chmod 644 /usr/share/keyrings/wazuh.gpg
fi

if [ ! -f /etc/apt/sources.list.d/wazuh.list ]; then
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
    apt-get update -y || warning_msg "Gagal update setelah menambah repo Wazuh."
fi

# Instalasi Wazuh Agent
if ! command -v /var/ossec/bin/wazuh-control &> /dev/null; then
    info_msg "Menginstal Wazuh Agent..."
    apt-get install -y wazuh-agent || error_exit "Gagal menginstal Wazuh Agent."
    success_msg "Wazuh Agent berhasil diinstal."
else
    info_msg "Wazuh Agent sudah terinstal."
fi

# 3. Instalasi YARA
# -----------------
info_msg "Memulai instalasi YARA..."
if ! command -v yara &> /dev/null; then
    apt-get install -y yara python3-yara || error_exit "Gagal menginstal YARA."
    success_msg "YARA berhasil diinstal."
else
    info_msg "YARA sudah terinstal."
fi

# 4. Instalasi ClamAV
# -------------------
info_msg "Memulai instalasi ClamAV..."
if ! command -v clamscan &> /dev/null; then
    apt-get install -y clamav clamav-daemon python3-pyclamd || error_exit "Gagal menginstal ClamAV."
    
    # Update database virus ClamAV
    info_msg "Memperbarui database virus ClamAV..."
    systemctl stop clamav-freshclam
    freshclam || warning_msg "Gagal update database ClamAV, akan dicoba lagi nanti."
    systemctl start clamav-freshclam
    systemctl enable clamav-freshclam
    
    # Start ClamAV daemon
    systemctl enable clamav-daemon
    systemctl start clamav-daemon
    success_msg "ClamAV berhasil diinstal dan dikonfigurasi."
else
    info_msg "ClamAV sudah terinstal."
    systemctl enable clamav-daemon clamav-freshclam 2>/dev/null || true
    systemctl restart clamav-daemon clamav-freshclam || warning_msg "Gagal restart services ClamAV."
fi

# Instalasi dependensi Python tambahan
info_msg "Menginstal dependensi Python untuk sistem SOC..."
pip3 install --upgrade pip
pip3 install GitPython requests python-magic yara-python pyclamd || warning_msg "Beberapa library Python mungkin gagal diinstal."

# 5. Pengumpulan Informasi Konfigurasi
# -------------------------------------
info_msg "Memulai pengumpulan informasi konfigurasi sistem SOC..."
SOC_CONFIG_DIR="/etc/soc-config"
mkdir -p "$SOC_CONFIG_DIR" || error_exit "Gagal membuat direktori konfigurasi $SOC_CONFIG_DIR"

# Konfigurasi Direktori Web & Apache
read -r -p "Masukkan path direktori web server (default: /var/www/html): " WEB_DIR
WEB_DIR=${WEB_DIR:-/var/www/html}
if [[ ! -d "$WEB_DIR" ]]; then
    mkdir -p "$WEB_DIR" || error_exit "Gagal membuat direktori $WEB_DIR."
    info_msg "Direktori $WEB_DIR telah dibuat."
fi

WEB_SERVER_USER="www-data"
WEB_SERVER_GROUP="www-data"

# Verifikasi user dan group web server
id "$WEB_SERVER_USER" &>/dev/null || error_exit "Pengguna web server '$WEB_SERVER_USER' tidak ditemukan."
getent group "$WEB_SERVER_GROUP" &>/dev/null || error_exit "Grup web server '$WEB_SERVER_GROUP' tidak ditemukan."

# Konfigurasi Server Monitoring (Wazuh Manager)
while true; do
    read -r -p "Masukkan IP Wazuh Manager (default: 192.168.1.10): " WAZUH_MANAGER_IP
    WAZUH_MANAGER_IP=${WAZUH_MANAGER_IP:-192.168.1.10}
    if validate_ip "$WAZUH_MANAGER_IP"; then
        break
    else
        warning_msg "IP address tidak valid. Silakan coba lagi."
    fi
done

read -r -p "Masukkan Username SSH di Server Monitoring (default: wazuh): " MONITOR_USER
MONITOR_USER=${MONITOR_USER:-wazuh}

read -r -p "Masukkan Path Direktori Backup Git di Server Monitoring (default: /var/backup/web): " REMOTE_GIT_BACKUP_PATH
REMOTE_GIT_BACKUP_PATH=${REMOTE_GIT_BACKUP_PATH:-/var/backup/web}

# Konfigurasi direktori dinamis untuk backup
info_msg "Konfigurasi direktori dinamis untuk backup..."
ENABLE_DYNAMIC_BACKUP="y"
BACKUP_DYNAMIC="true"

LOCAL_DYNAMIC_STAGING_DIR="/var/soc-backup/staging"
mkdir -p "$LOCAL_DYNAMIC_STAGING_DIR" || error_exit "Gagal membuat direktori $LOCAL_DYNAMIC_STAGING_DIR"
chmod 750 "$LOCAL_DYNAMIC_STAGING_DIR" || warning_msg "Gagal mengatur permission direktori staging."

REMOTE_DYNAMIC_BACKUP_PATH="${REMOTE_GIT_BACKUP_PATH}/dynamic"

LOCAL_DYNAMIC_RESTORE_CACHE_DIR="/var/soc-backup/restore-cache"
mkdir -p "$LOCAL_DYNAMIC_RESTORE_CACHE_DIR" || error_exit "Gagal membuat direktori $LOCAL_DYNAMIC_RESTORE_CACHE_DIR"
chmod 750 "$LOCAL_DYNAMIC_RESTORE_CACHE_DIR" || warning_msg "Gagal mengatur permission direktori restore cache."

# Direktori untuk eradication (Karantina, YARA, ClamAV)
info_msg "Konfigurasi direktori untuk Eradication..."
QUARANTINE_DIR="/var/soc-quarantine"
mkdir -p "$QUARANTINE_DIR" || error_exit "Gagal membuat direktori $QUARANTINE_DIR"
chmod 750 "$QUARANTINE_DIR" || warning_msg "Gagal mengatur permission direktori karantina."

YARA_RULES_DIR="/var/ossec/etc/rules/yara"
mkdir -p "$YARA_RULES_DIR" || warning_msg "Gagal membuat direktori YARA rules"
chmod 750 "$YARA_RULES_DIR" || warning_msg "Gagal mengatur permission direktori YARA rules."

CLAMD_SOCKET="/var/run/clamav/clamd.ctl"

# Konfigurasi Rule IDs Wazuh untuk Containment
DEFACE_RULE_IDS="550,554,5501,5502,5503,5504,100001,100002"
ATTACK_RULE_IDS="5710,5712,5715,5760,100003,100004"

# Konfigurasi pengguna Wazuh
WAZUH_USER="wazuh"
WAZUH_GROUP="wazuh"
SHARED_AR_GROUP="soc-operators"

# Buat grup shared untuk Active Response
if ! getent group "$SHARED_AR_GROUP" &>/dev/null; then
    groupadd "$SHARED_AR_GROUP" || warning_msg "Gagal membuat grup $SHARED_AR_GROUP."
    success_msg "Grup $SHARED_AR_GROUP berhasil dibuat."
fi

# Tambahkan user wazuh ke grup shared (jika user wazuh ada)
if id "$WAZUH_USER" &>/dev/null; then
    usermod -a -G "$SHARED_AR_GROUP" "$WAZUH_USER" || warning_msg "Gagal menambahkan $WAZUH_USER ke grup $SHARED_AR_GROUP."
fi

# Tambahkan user web server ke grup shared
usermod -a -G "$SHARED_AR_GROUP" "$WEB_SERVER_USER" || warning_msg "Gagal menambahkan $WEB_SERVER_USER ke grup $SHARED_AR_GROUP."

# Konfigurasi Integrasi YETI (CTI) - default disabled untuk simplifikasi
YETI_ENABLED="false"
YETI_API_URL=""
YETI_API_KEY=""

# Password untuk backup dan restore
info_msg "Mengatur password untuk backup dan restore..."
while true; do
    read -s -p "Masukkan password untuk backup dan restore (minimal 12 karakter): " BACKUP_PASSWORD
    echo
    if [ ${#BACKUP_PASSWORD} -ge 12 ]; then
        break
    else
        warning_msg "Password harus minimal 12 karakter. Silakan coba lagi."
    fi
done

ENCODED_PASSWORD=$(echo -n "$BACKUP_PASSWORD" | base64)

info_msg "Password default untuk sistem: $BACKUP_PASSWORD"
warning_msg "Pastikan untuk mengubah password ini setelah instalasi selesai."

# Path Kunci SSH akan diatur di bagian 11 dan disimpan di sini
SSH_IDENTITY_FILE_PATH=""

# 6. Konfigurasi Wazuh Agent
# --------------------------
info_msg "Mengkonfigurasi Wazuh Agent untuk terhubung ke Wazuh Manager..."

# Backup konfigurasi Wazuh yang ada
if [ -f /var/ossec/etc/ossec.conf ]; then
    cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.backup.$(date +%Y%m%d_%H%M%S)
fi

# Konfigurasi dasar ossec.conf
cat > /var/ossec/etc/ossec.conf << EOF
<ossec_config>
  <client>
    <server>
      <address>$WAZUH_MANAGER_IP</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <crypto_method>aes</crypto_method>
    <notify_time>30</notify_time>
    <time-reconnect>60</time-reconnect>
    <auto_restart>yes</auto_restart>
  </client>

  <client_buffer>
    <disabled>no</disabled>
    <queue_size>5000</queue_size>
    <events_per_second>500</events_per_second>
  </client_buffer>

  <logging>
    <log_format>plain</log_format>
  </logging>

  <rootcheck>
    <disabled>no</disabled>
    <check_files>yes</check_files>
    <check_trojans>yes</check_trojans>
    <check_dev>yes</check_dev>
    <check_sys>yes</check_sys>
    <check_pids>yes</check_pids>
    <check_ports>yes</check_ports>
    <check_if>yes</check_if>
    <frequency>43200</frequency>
    <rootkit_files>/var/ossec/etc/rootcheck/rootkit_files.txt</rootkit_files>
    <rootkit_trojans>/var/ossec/etc/rootcheck/rootkit_trojans.txt</rootkit_trojans>
    <system_audit>/var/ossec/etc/rootcheck/system_audit_rcl.txt</system_audit>
    <system_audit>/var/ossec/etc/rootcheck/system_audit_ssh.txt</system_audit>
    <system_audit>/var/ossec/etc/rootcheck/cis_debian_linux_rcl.txt</system_audit>
  </rootcheck>

  <wodle name="cis-cat">
    <disabled>yes</disabled>
    <timeout>1800</timeout>
    <interval>1d</interval>
    <scan-on-start>yes</scan-on-start>
  </wodle>

  <wodle name="osquery">
    <disabled>yes</disabled>
    <run_daemon>yes</run_daemon>
    <log_path>/var/log/osquery/osqueryd.results.log</log_path>
    <config_path>/etc/osquery/osquery.conf</config_path>
    <add_labels>yes</add_labels>
  </wodle>

  <wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>
    <hardware>yes</hardware>
    <os>yes</os>
    <network>yes</network>
    <packages>yes</packages>
    <ports all="no">yes</ports>
    <processes>yes</processes>
  </wodle>

  <sca>
    <enabled>yes</enabled>
    <scan_on_start>yes</scan_on_start>
    <interval>12h</interval>
    <skip_nfs>yes</skip_nfs>
  </sca>

  <vulnerability-detector>
    <enabled>no</enabled>
    <interval>5m</interval>
    <ignore_time>6h</ignore_time>
    <run_on_start>yes</run_on_start>
    <provider name="canonical">
      <enabled>yes</enabled>
      <os>trusty</os>
      <os>xenial</os>
      <os>bionic</os>
      <os>focal</os>
      <os>jammy</os>
      <update_interval>1h</update_interval>
    </provider>
  </vulnerability-detector>

  <!-- File Integrity Monitoring for web directory -->
  <syscheck>
    <disabled>no</disabled>
    <frequency>300</frequency>
    <scan_on_start>yes</scan_on_start>
    
    <!-- Monitor web directory -->
    <directories whodata="yes" report_changes="yes" check_all="yes">$WEB_DIR</directories>
    
    <!-- Monitor system directories -->
    <directories check_all="yes">/etc,/usr/bin,/usr/sbin</directories>
    <directories check_all="yes">/bin,/sbin,/boot</directories>
    
    <!-- Monitor log directories -->
    <directories check_all="yes">/var/log</directories>

    <!-- Ignore common temporary files -->
    <ignore>/etc/mtab</ignore>
    <ignore>/etc/hosts.deny</ignore>
    <ignore>/etc/mail/statistics</ignore>
    <ignore>/etc/random-seed</ignore>
    <ignore>/etc/random.seed</ignore>
    <ignore>/etc/adjtime</ignore>
    <ignore>/etc/httpd/logs</ignore>
    <ignore>/etc/utmpx</ignore>
    <ignore>/etc/wtmpx</ignore>
    <ignore>/etc/cups/certs</ignore>
    <ignore>/etc/dumpdates</ignore>
    <ignore>/etc/svc/volatile</ignore>

    <nodiff>/etc/ssl/private.key</nodiff>

    <skip_nfs>yes</skip_nfs>
    <skip_dev>yes</skip_dev>
    <skip_proc>yes</skip_proc>
    <skip_sys>yes</skip_sys>

    <process_priority>10</process_priority>
    <max_eps>50</max_eps>
    <sync_enabled>yes</sync_enabled>
    <sync_interval>5m</sync_interval>
    <sync_max_interval>1h</sync_max_interval>
  </syscheck>

  <!-- Log analysis -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/dpkg.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/kern.log</location>
  </localfile>

  <!-- Apache logs -->
  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/apache2/error.log</location>
  </localfile>

  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/apache2/access.log</location>
  </localfile>

  <!-- SOC System logs -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/wazuh/active-response/containment.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/wazuh/active-response/eradication.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/wazuh/active-response/restore_auto.log</location>
  </localfile>

  <!-- Active Response Commands -->
  <command>
    <name>soc_containment</name>
    <executable>containment.py</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>soc_eradication</name>
    <executable>eradication.py</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>soc_restore</name>
    <executable>restore_auto.py</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <!-- Active Response Rules -->
  <active-response>
    <command>soc_containment</command>
    <location>local</location>
    <rules_id>550,554,5501,5502,5503,5504,100001,100002</rules_id>
  </active-response>

  <active-response>
    <command>soc_eradication</command>
    <location>local</location>
    <rules_id>5710,5712,5715,5760,100003,100004</rules_id>
  </active-response>

  <active-response>
    <command>soc_restore</command>
    <location>local</location>
    <rules_id>550,554,5501,5502,5503,5504,100001,100002</rules_id>
  </active-response>

</ossec_config>
EOF

success_msg "Konfigurasi Wazuh Agent berhasil dibuat."

# Membuat direktori untuk Active Response scripts
mkdir -p /var/ossec/active-response/bin
mkdir -p /var/log/wazuh/active-response
chown -R "$WAZUH_USER:$WAZUH_GROUP" /var/log/wazuh 2>/dev/null || true

# 7. Download dan Setup YARA Rules
# ---------------------------------
info_msg "Mengunduh dan mengatur YARA rules untuk deteksi malware..."

# Membuat custom YARA rule untuk deteksi defacement
cat > "$YARA_RULES_DIR/custom_defacement.yar" << 'EOF'
rule Defacement_Indicators
{
    meta:
        description = "Deteksi indikator defacement pada file web"
        author = "SOC System"
        date = "2024-01-01"
        
    strings:
        $deface1 = "hacked by" nocase
        $deface2 = "defaced by" nocase
        $deface3 = "owned by" nocase
        $deface4 = "pwned by" nocase
        $deface5 = "r00ted by" nocase
        $deface6 = "cracked by" nocase
        $suspicious1 = "eval(base64_decode" nocase
        $suspicious2 = "system(" nocase
        $suspicious3 = "shell_exec(" nocase
        $suspicious4 = "passthru(" nocase
        $suspicious5 = "exec(" nocase
        $webshell1 = "FilesMan" nocase
        $webshell2 = "c99shell" nocase
        $webshell3 = "r57shell" nocase
        $webshell4 = "webshell" nocase
        
    condition:
        any of them
}

rule PHP_Webshell_Generic
{
    meta:
        description = "Generic PHP webshell detection"
        author = "SOC System"
        
    strings:
        $php = "<?php"
        $eval = "eval("
        $base64 = "base64_decode"
        $system = /system\s*\(/
        $exec = /exec\s*\(/
        $shell = /shell_exec\s*\(/
        $passthru = /passthru\s*\(/
        
    condition:
        $php and ($eval or ($base64 and (any of ($system, $exec, $shell, $passthru))))
}
EOF

chown -R "$WAZUH_USER:$WAZUH_GROUP" "$YARA_RULES_DIR" 2>/dev/null || true
chmod -R 644 "$YARA_RULES_DIR"/*.yar 2>/dev/null || true

success_msg "YARA rules berhasil diunduh dan dikonfigurasi."

# 8. Membuat File Konfigurasi /etc/soc-config/config.conf
# --------------------------------------------------------
info_msg "Membuat file konfigurasi $SOC_CONFIG_DIR/config.conf..."

# Inisialisasi variabel untuk pattern eradication
DEFAULT_ERADICATION_PATTERNS='(?i)(eval\s*\(base64_decode\s*\()|\
(?i)(passthru\s*\()|\
(?i)(shell_exec\s*\()|\
(?i)(system\s*\()|\
(?i)(exec\s*\()|\
(?i)(preg_replace\s*\(.*\/e\s*\))|\
(?i)(FilesMan|phpfm|P\.A\.S\.|\bWebShell\b|r57shell|c99shell)|\
(?i)(document\.write\s*\(\s*unescape\s*\()|\
(?i)(<iframe\s*src\s*=\s*["'\''"]javascript:)|\
(?i)(fsockopen|pfsockopen)\s*\('

# 9. Membuat dan Menyesuaikan Skrip Lokal (soc-backup-dynamic)
# -------------------------------------------------------------
info_msg "Membuat skrip /usr/local/bin/soc-backup-dynamic..."

cat > "/usr/local/bin/soc-backup-dynamic" << 'BACKUP_DYNAMIC_SCRIPT_EOF'
#!/bin/bash
# SOC Dynamic Backup Script
# Backup file dinamis ke server monitoring
set -euo pipefail

CONFIG_FILE="/etc/soc-config/config.conf"
if [ ! -f "$CONFIG_FILE" ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [ERROR] File konfigurasi '$CONFIG_FILE' tidak ditemukan." >&2
    exit 1
fi

# shellcheck source=/dev/null
source "$CONFIG_FILE"

# Verifikasi variabel yang dibutuhkan
REQUIRED_VARS=("WEB_DIR" "LOCAL_DYNAMIC_STAGING_DIR" "DYNAMIC_DIRS")
for var in "${REQUIRED_VARS[@]}"; do
    if [ -z "${!var+x}" ] || [ -z "${!var}" ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') - [ERROR] Variabel '$var' tidak ditemukan atau kosong di '$CONFIG_FILE'." >&2
        exit 1
    fi
done

if [ "$BACKUP_DYNAMIC" != "true" ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [INFO] Backup dinamis tidak diaktifkan." >&2
    exit 0
fi

# Membuat arsip untuk setiap direktori dinamis
cd "$WEB_DIR" || exit 1
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')

for dir in "${DYNAMIC_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        ARCHIVE_NAME="dynamic_${dir}_${TIMESTAMP}.tar.gz"
        ARCHIVE_PATH="$LOCAL_DYNAMIC_STAGING_DIR/$ARCHIVE_NAME"
        
        echo "$(date '+%Y-%m-%d %H:%M:%S') - [INFO] Membuat arsip untuk direktori '$dir'..."
        if tar -czf "$ARCHIVE_PATH" "$dir" 2>/dev/null; then
            echo "$(date '+%Y-%m-%d %H:%M:%S') - [SUCCESS] Arsip '$ARCHIVE_NAME' berhasil dibuat."
        else
            echo "$(date '+%Y-%m-%d %H:%M:%S') - [WARNING] Gagal membuat arsip untuk direktori '$dir'." >&2
        fi
    else
        echo "$(date '+%Y-%m-%d %H:%M:%S') - [WARNING] Direktori dinamis '$dir' tidak ditemukan di '$WEB_DIR'." >&2
    fi
done

echo "$(date '+%Y-%m-%d %H:%M:%S') - [INFO] Backup dinamis selesai."
BACKUP_DYNAMIC_SCRIPT_EOF

chmod +x "/usr/local/bin/soc-backup-dynamic"
success_msg "Skrip /usr/local/bin/soc-backup-dynamic berhasil dibuat."

# Verifikasi variabel penting setelah pengumpulan input dan sebelum penggunaan utama
CRITICAL_VARS=("WEB_DIR" "WAZUH_MANAGER_IP" "MONITOR_USER" "REMOTE_GIT_BACKUP_PATH")
for var_check in "${CRITICAL_VARS[@]}"; do
    if [ -z "${!var_check+x}" ] || [ -z "${!var_check}" ]; then
        error_exit "Variabel kritis '$var_check' tidak ditemukan atau kosong. Periksa konfigurasi."
    fi
done

# 10. Pengaturan Git di Direktori Web Server
# -------------------------------------------
info_msg "Memulai pengaturan Git di direktori web: $WEB_DIR..."

cd "$WEB_DIR" || error_exit "Gagal masuk ke direktori $WEB_DIR"

# Inisialisasi repository Git jika belum ada
if [ ! -d ".git" ]; then
    info_msg "Menginisialisasi repository Git di $WEB_DIR..."
    git init || error_exit "Gagal menginisialisasi repository Git."
    success_msg "Repository Git berhasil diinisialisasi."
else
    info_msg "Repository Git sudah ada di $WEB_DIR."
fi

# Konfigurasi Git user (diperlukan untuk commit)
read -r -p "Masukkan nama untuk Git commits (default: SOC System): " GIT_USER_NAME
GIT_USER_NAME=${GIT_USER_NAME:-"SOC System"}

read -r -p "Masukkan email untuk Git commits (default: soc@localhost): " GIT_USER_EMAIL
GIT_USER_EMAIL=${GIT_USER_EMAIL:-"soc@localhost"}

git config --local user.name "$GIT_USER_NAME"
git config --local user.email "$GIT_USER_EMAIL"
success_msg "Konfigurasi Git user berhasil: $GIT_USER_NAME <$GIT_USER_EMAIL>"

# Membuat .gitignore yang sesuai untuk web server
cat > ".gitignore" << 'GITIGNORE_EOF'
# Log files
*.log
logs/
log/

# Temporary files
*.tmp
*.temp
.tmp/
.temp/

# Cache directories
cache/
.cache/

# Upload directories (comment out if you want to track uploads)
uploads/
upload/

# Session files
sessions/
.sessions/

# Configuration files with sensitive data
config.php
.env
.env.*

# OS generated files
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db

# IDE files
.vscode/
.idea/
*.swp
*.swo
*~

# Backup files
*.bak
*.backup
GITIGNORE_EOF

# Menambahkan maintenance.html (halaman maintenance)
cat > "maintenance.html" << 'MAINTENANCE_EOF'
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Maintenance Mode - Sistem dalam Pemeliharaan</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            margin: 0;
            padding: 0;
            height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            color: white;
        }
        .container {
            text-align: center;
            padding: 40px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 20px;
            backdrop-filter: blur(10px);
            box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.37);
        }
        h1 {
            font-size: 2.5em;
            margin-bottom: 20px;
            color: #fff;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        p {
            font-size: 1.2em;
            margin-bottom: 15px;
            color: #f0f0f0;
        }
        .icon {
            font-size: 4em;
            margin-bottom: 20px;
            opacity: 0.8;
        }
        .security-notice {
            background: rgba(255, 165, 0, 0.2);
            padding: 15px;
            border-radius: 10px;
            margin-top: 20px;
            border-left: 4px solid #FFA500;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">🔧</div>
        <h1>Sistem dalam Mode Pemeliharaan</h1>
        <p>Website ini sedang dalam mode maintenance untuk alasan keamanan.</p>
        <p>Kami sedang melakukan pemeriksaan dan perbaikan sistem.</p>
        <div class="security-notice">
            <p><strong>Security Operations Center (SOC)</strong></p>
            <p>Sistem keamanan aktif dan memantau semua aktivitas.</p>
        </div>
        <p>Silakan kembali beberapa saat lagi.</p>
        <p>Terima kasih atas pengertian Anda.</p>
    </div>
</body>
</html>
MAINTENANCE_EOF

# Mengatur kepemilikan file
chown "$WEB_SERVER_USER:$WEB_SERVER_GROUP" "maintenance.html" .gitignore

# Melakukan initial commit
git add .
if git commit -m "Initial SOC setup commit"; then
    success_msg "Initial commit berhasil."
else
    info_msg "Tidak ada perubahan untuk di-commit (mungkin sudah ada commit sebelumnya)."
fi

# Mengatur remote untuk backup (akan dikonfigurasi nanti setelah SSH key)
info_msg "Remote Git akan dikonfigurasi setelah setup SSH key."

# 11. Pengaturan Grup dan Izin untuk Integrasi Wazuh Active Response
# -------------------------------------------------------------------
info_msg "Mengatur izin dan grup untuk integrasi SOC..."

# Mengatur izin direktori web agar dapat diakses oleh grup shared
chgrp -R "$SHARED_AR_GROUP" "$WEB_DIR" || warning_msg "Gagal mengubah grup direktori web."
chmod -R g+rw "$WEB_DIR" || warning_msg "Gagal mengubah izin direktori web."
chmod g+s "$WEB_DIR" || warning_msg "Gagal mengatur SGID pada direktori web."

# Mengatur izin direktori SOC
chgrp -R "$SHARED_AR_GROUP" "$SOC_CONFIG_DIR" "$LOCAL_DYNAMIC_STAGING_DIR" "$LOCAL_DYNAMIC_RESTORE_CACHE_DIR" "$QUARANTINE_DIR" 2>/dev/null || true
chmod -R g+rw "$LOCAL_DYNAMIC_STAGING_DIR" "$LOCAL_DYNAMIC_RESTORE_CACHE_DIR" "$QUARANTINE_DIR" 2>/dev/null || true

success_msg "Pengaturan grup dan izin selesai."

# 12. Pengaturan Cron Job untuk Backup Otomatis
# ----------------------------------------------
info_msg "Pengaturan Backup Otomatis (Cron Job)..."

# Membuat cron job untuk backup reguler
CRON_BACKUP_CMD="/usr/local/bin/soc-backup >> /var/log/soc-backup.log 2>&1"
CRON_DYNAMIC_CMD="/usr/local/bin/soc-backup-dynamic >> /var/log/soc-backup-dynamic.log 2>&1"

# Cek apakah cron job sudah ada
if ! crontab -l 2>/dev/null | grep -q "soc-backup"; then
    info_msg "Menambahkan cron job untuk backup otomatis..."
    (crontab -l 2>/dev/null; echo "# SOC Backup Otomatis") | crontab -
    (crontab -l 2>/dev/null; echo "0 */6 * * * $CRON_BACKUP_CMD") | crontab -
    (crontab -l 2>/dev/null; echo "30 */2 * * * $CRON_DYNAMIC_CMD") | crontab -
    success_msg "Cron job backup berhasil ditambahkan (setiap 6 jam untuk backup utama, setiap 2 jam untuk backup dinamis)."
else
    info_msg "Cron job backup sudah ada."
fi

# 13. Otomatisasi Penuh Konfigurasi SSH ke Server Monitoring (Direktori Dinamis)
# ---------------------------------------------------------------------------------
info_msg "Konfigurasi Kunci SSH untuk koneksi ke server monitoring ($MONITOR_USER@$WAZUH_MANAGER_IP)..."

SSH_KEY_NAME="id_rsa_soc_backup"
SSH_IDENTITY_FILE_PATH="/root/.ssh/$SSH_KEY_NAME"

mkdir -p "/root/.ssh"
chmod 700 "/root/.ssh"

if [ ! -f "$SSH_IDENTITY_FILE_PATH" ]; then
    info_msg "Membuat SSH key pair untuk backup..."
    ssh-keygen -t rsa -b 4096 -f "$SSH_IDENTITY_FILE_PATH" -N "" -C "soc-backup@$(hostname)"
    success_msg "SSH key pair berhasil dibuat: $SSH_IDENTITY_FILE_PATH"
else
    info_msg "SSH key sudah ada: $SSH_IDENTITY_FILE_PATH"
fi

CONTROL_PATH="/tmp/ssh_soc_control_$$"

info_msg "Memulai koneksi master SSH. Anda akan diminta password untuk '$MONITOR_USER' SATU KALI."

ssh -M -S "$CONTROL_PATH" -o ControlPersist=60s "$MONITOR_USER@$WAZUH_MANAGER_IP" -Nf
if [ $? -ne 0 ]; then
    error_exit "Gagal membuat koneksi master SSH. Periksa koneksi, nama pengguna, atau password."
fi
success_msg "Koneksi master SSH berhasil dibuat."


# --- PERUBAHAN DINAMIS ---
# Langkah 1: Membangun dan mengeksekusi script persiapan di remote server secara dinamis

info_msg "Mempersiapkan direktori, kepemilikan, dan Git di server monitoring..."

# 'printf %q' adalah cara yang aman untuk meng-quote variabel agar dapat digunakan
# di shell lain tanpa risiko command injection.
REMOTE_PATH_QUOTED=$(printf '%q' "$REMOTE_GIT_BACKUP_PATH")
REMOTE_USER_QUOTED=$(printf '%q' "$MONITOR_USER")

# Membangun blok perintah sebagai satu string untuk dikirim ke remote server.
REMOTE_SCRIPT="
echo \"[REMOTE] Path backup yang akan disiapkan: ${REMOTE_PATH_QUOTED}\";
echo \"[REMOTE] Membuat direktori ${REMOTE_PATH_QUOTED}...\";
mkdir -p ${REMOTE_PATH_QUOTED};

echo \"[REMOTE] Mengatur kepemilikan untuk pengguna ${REMOTE_USER_QUOTED}...\";
if command -v sudo &> /dev/null; then
    sudo chown -R ${REMOTE_USER_QUOTED}:${REMOTE_USER_QUOTED} ${REMOTE_PATH_QUOTED};
else
    chown -R ${REMOTE_USER_QUOTED}:${REMOTE_USER_QUOTED} ${REMOTE_PATH_QUOTED};
fi;

echo \"[REMOTE] Inisialisasi Git bare repository di ${REMOTE_PATH_QUOTED}...\";
if [ ! -d \"${REMOTE_PATH_QUOTED}/refs\" ]; then
    git init --bare ${REMOTE_PATH_QUOTED};
else
    echo \"[REMOTE] Git repository sudah ada.\";
fi;

echo \"[REMOTE] Persiapan selesai.\";
"

# Eksekusi blok perintah yang sudah dibangun menggunakan koneksi master
ssh -S "$CONTROL_PATH" "$MONITOR_USER@$WAZUH_MANAGER_IP" "$REMOTE_SCRIPT"

if [ $? -ne 0 ]; then
    warning_msg "Beberapa perintah persiapan di server remote mungkin gagal. Periksa output di atas."
else
    success_msg "Persiapan di server monitoring berhasil diselesaikan."
fi
# --- AKHIR PERUBAHAN DINAMIS ---


# Langkah 2: Salin kunci SSH menggunakan koneksi master yang sama
info_msg "Menyalin kunci SSH publik (tanpa meminta password lagi)..."
ssh-copy-id -o "ControlPath=$CONTROL_PATH" -i "$SSH_IDENTITY_FILE_PATH.pub" "$MONITOR_USER@$WAZUH_MANAGER_IP"
if [ $? -ne 0 ]; then
    ssh -S "$CONTROL_PATH" -O exit "$MONITOR_USER@$WAZUH_MANAGER_IP" 2>/dev/null || true
    error_exit "Gagal menyalin kunci SSH. Otomatisasi gagal."
fi
success_msg "Kunci SSH publik berhasil disalin secara otomatis."


# Langkah 3: Tutup koneksi master
info_msg "Menutup koneksi master SSH..."
ssh -S "$CONTROL_PATH" -O exit "$MONITOR_USER@$WAZUH_MANAGER_IP" 2>/dev/null || true
success_msg "Konfigurasi koneksi SSH telah selesai."
echo ""


# Mengatur remote Git sekarang setelah SSH key berhasil terpasang
cd "$WEB_DIR" || error_exit "Gagal masuk ke direktori $WEB_DIR"
REMOTE_GIT_URL="$MONITOR_USER@$WAZUH_MANAGER_IP:$REMOTE_GIT_BACKUP_PATH"

git remote remove monitoring 2>/dev/null || true
git remote add monitoring "$REMOTE_GIT_URL" || error_exit "Gagal mengatur remote Git."
success_msg "Remote Git 'monitoring' berhasil dikonfigurasi: $REMOTE_GIT_URL"

# 14. Menulis File Konfigurasi config.conf
# ----------------------------------------
info_msg "Menulis file konfigurasi lengkap: $SOC_CONFIG_DIR/config.conf..."

# Definisikan array DYNAMIC_DIRS
CONFIG_DYNAMIC_DIRS_ARRAY=("uploads" "cache" "tmp" "sessions")
CONFIG_DYNAMIC_DIRS_STRING="($(printf "\"%s\" " "${CONFIG_DYNAMIC_DIRS_ARRAY[@]}" | sed 's/ $//'))"

cat > "$SOC_CONFIG_DIR/config.conf" << EOF
# Konfigurasi Sistem SOC - NIST 800-61 Incident Response
# =======================================================

# Konfigurasi Umum
WEB_DIR="$WEB_DIR"
WEB_SERVER_USER="$WEB_SERVER_USER"
WEB_SERVER_GROUP="$WEB_SERVER_GROUP"
PASSWORD="$ENCODED_PASSWORD"

# Konfigurasi Server Monitoring/Wazuh Manager
MONITOR_IP="$WAZUH_MANAGER_IP"
MONITOR_USER="$MONITOR_USER"
WAZUH_MANAGER_IP="$WAZUH_MANAGER_IP"

# Konfigurasi Backup
REMOTE_GIT_BACKUP_PATH="$REMOTE_GIT_BACKUP_PATH"
SSH_IDENTITY_FILE="$SSH_IDENTITY_FILE_PATH"

# Konfigurasi Backup Dinamis
BACKUP_DYNAMIC="$BACKUP_DYNAMIC"
LOCAL_DYNAMIC_STAGING_DIR="$LOCAL_DYNAMIC_STAGING_DIR"
REMOTE_DYNAMIC_BACKUP_PATH="$REMOTE_DYNAMIC_BACKUP_PATH"
LOCAL_DYNAMIC_RESTORE_CACHE_DIR="$LOCAL_DYNAMIC_RESTORE_CACHE_DIR"
DYNAMIC_DIRS=$CONFIG_DYNAMIC_DIRS_STRING

# Konfigurasi Eradication
QUARANTINE_DIR="$QUARANTINE_DIR"
YARA_RULES_DIR="$YARA_RULES_DIR"
CLAMD_SOCKET="$CLAMD_SOCKET"
ERADICATION_SUSPICIOUS_PATTERNS="$DEFAULT_ERADICATION_PATTERNS"

# Konfigurasi Containment
DEFACE_RULE_IDS="$DEFACE_RULE_IDS"
ATTACK_RULE_IDS="$ATTACK_RULE_IDS"

# Konfigurasi Pengguna dan Grup
WAZUH_USER="$WAZUH_USER"
WAZUH_GROUP="$WAZUH_GROUP"
SHARED_AR_GROUP="$SHARED_AR_GROUP"

# Konfigurasi Integrasi YETI (CTI)
YETI_ENABLED="$YETI_ENABLED"
YETI_API_URL="$YETI_API_URL"
YETI_API_KEY="$YETI_API_KEY"
EOF

# Mengatur izin file konfigurasi
chown "root:$SHARED_AR_GROUP" "$SOC_CONFIG_DIR/config.conf"
chmod 640 "$SOC_CONFIG_DIR/config.conf"
success_msg "File konfigurasi $SOC_CONFIG_DIR/config.conf berhasil dibuat."

# 15. Menyalin dan Menyiapkan Script SOC
# ---------------------------------------
info_msg "Menyiapkan script-script SOC..."

# Membuat symbolic link untuk backward compatibility
if [ ! -f "/etc/web-backup/config.conf" ]; then
    mkdir -p "/etc/web-backup"
    ln -sf "$SOC_CONFIG_DIR/config.conf" "/etc/web-backup/config.conf"
    info_msg "Symbolic link backward compatibility dibuat: /etc/web-backup/config.conf"
fi
# Menyalin script containment.py ke Active Response directory
if [ -f "$SCRIPT_DIR/containment.py" ]; then
    cp "$SCRIPT_DIR/containment.py" "/var/ossec/active-response/bin/"
    chmod +x "/var/ossec/active-response/bin/containment.py"
    cp "$SCRIPT_DIR/containment.py" "/usr/local/bin/"
    chmod +x "/usr/local/bin/containment.py"
    success_msg "Script containment.py berhasil disalin."
else
    warning_msg "File containment.py tidak ditemukan di $SCRIPT_DIR. Melewati penyalinan."
fi

# Menyalin script eradication.py ke Active Response directory
if [ -f "$SCRIPT_DIR/eradication.py" ]; then
    cp "$SCRIPT_DIR/eradication.py" "/var/ossec/active-response/bin/"
    chmod +x "/var/ossec/active-response/bin/eradication.py"
    cp "$SCRIPT_DIR/eradication.py" "/usr/local/bin/"
    chmod +x "/usr/local/bin/eradication.py"
    success_msg "Script eradication.py berhasil disalin."
else
    warning_msg "File eradication.py tidak ditemukan di $SCRIPT_DIR. Melewati penyalinan."
fi

# Menyalin script restore_auto.py ke Active Response directory
if [ -f "$SCRIPT_DIR/restore_auto.py" ]; then
    cp "$SCRIPT_DIR/restore_auto.py" "/var/ossec/active-response/bin/"
    chmod +x "/var/ossec/active-response/bin/restore_auto.py"
    cp "$SCRIPT_DIR/restore_auto.py" "/usr/local/bin/"
    chmod +x "/usr/local/bin/restore_auto.py"
    success_msg "Script restore_auto.py berhasil disalin."
else
    warning_msg "File restore_auto.py tidak ditemukan di $SCRIPT_DIR. Melewati penyalinan."
fi

# Menyalin script backup.sh sebagai soc-backup
if [ -f "$SCRIPT_DIR/backup.sh" ]; then
    cp "$SCRIPT_DIR/backup.sh" "/usr/local/bin/soc-backup"
    chmod +x "/usr/local/bin/soc-backup"
    success_msg "Script backup.sh berhasil disalin sebagai soc-backup."
else
    warning_msg "File backup.sh tidak ditemukan di $SCRIPT_DIR. Melewati penyalinan."
fi

# Menyalin script restore.py sebagai web-restore
if [ -f "$SCRIPT_DIR/restore.py" ]; then
    cp "$SCRIPT_DIR/restore.py" "/usr/local/bin/web-restore"
    chmod +x "/usr/local/bin/web-restore"
    success_msg "Script restore.py berhasil disalin sebagai web-restore."
else
    warning_msg "File restore.py tidak ditemukan di $SCRIPT_DIR. Melewati penyalinan."
fi
# 16. Mengatur Izin dan Kepemilikan Script
# ----------------------------------------
info_msg "Mengatur izin dan kepemilikan script SOC..."

# Mengatur kepemilikan untuk Active Response scripts
chown "$WAZUH_USER:$WAZUH_GROUP" /var/ossec/active-response/bin/*.py 2>/dev/null || true

# Mengatur izin eksekusi untuk semua script SOC
chmod +x /usr/local/bin/soc-* 2>/dev/null || true
chmod +x /usr/local/bin/web-* 2>/dev/null || true

success_msg "Izin dan kepemilikan script berhasil diatur."

# 17. Start dan Enable Wazuh Agent
# --------------------------------
info_msg "Memulai dan mengaktifkan Wazuh Agent..."

systemctl enable wazuh-agent
systemctl restart wazuh-agent

# Tunggu beberapa detik untuk koneksi
sleep 5

if systemctl is-active --quiet wazuh-agent; then
    success_msg "Wazuh Agent berhasil diaktifkan dan berjalan."
    info_msg "Pastikan untuk mendaftarkan agent ini di Wazuh Manager dengan:"
    info_msg "/var/ossec/bin/agent-auth -m $WAZUH_MANAGER_IP"
else
    warning_msg "Wazuh Agent mungkin belum berjalan dengan baik. Periksa log: journalctl -u wazuh-agent"
fi

# 18. Tes Backup Awal
# -------------------
info_msg "Melakukan backup awal untuk pengujian..."

cd "$WEB_DIR" || error_exit "Gagal masuk ke direktori $WEB_DIR"

# Buat file test sederhana jika direktori kosong
if [ ! -f "index.html" ]; then
    cat > "index.html" << 'INDEX_EOF'
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SOC System - Security Operations Center</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            margin: 0;
            padding: 20px;
            color: white;
            min-height: 100vh;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            text-align: center;
            padding: 40px;
        }
        h1 {
            font-size: 3em;
            margin-bottom: 20px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        .status {
            background: rgba(0, 255, 0, 0.2);
            padding: 20px;
            border-radius: 10px;
            margin: 20px 0;
            border-left: 4px solid #00FF00;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ SOC System Active</h1>
        <div class="status">
            <h2>Security Operations Center</h2>
            <p>Sistem monitoring keamanan berdasarkan NIST 800-61 Incident Response Life Cycle aktif.</p>
            <p>Web server dilindungi oleh Wazuh, YARA, dan ClamAV.</p>
        </div>
        <p>Sistem diinstal pada: $(date)</p>
    </div>
</body>
</html>
INDEX_EOF
    chown "$WEB_SERVER_USER:$WEB_SERVER_GROUP" "index.html"
fi

# Commit perubahan
git add .
git commit -m "SOC initial setup - $(date)" || true

info_msg "Backup awal selesai."
success_msg "Instalasi Sistem SOC telah selesai!"
echo "================================================================="
echo "            INSTALASI SELESAI & LANGKAH SELANJUTNYA              "
echo "================================================================="
echo "1. Pastikan SSH key public telah ditambahkan ke server monitoring."
echo "2. Daftarkan agent Wazuh di Manager: /var/ossec/bin/agent-auth -m $WAZUH_MANAGER_IP"
echo "3. Lakukan tes backup manual: sudo /usr/local/bin/soc-backup"
echo "4. Periksa log di /var/log/soc-backup.log dan /var/log/wazuh/active-response/"
echo "5. Log instalasi lengkap tersedia di: $LOG_FILE"
echo "================================================================="
