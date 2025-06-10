#!/bin/bash

# Script Instalasi untuk Server Monitoring (Backup Repository)
# -------------------------------------------------------------

# Fungsi untuk menampilkan pesan error dan keluar
error_exit() { # Menggunakan format standar seperti install.sh
    echo -e "\e[31m[ERROR] $(date '+%Y-%m-%d %H:%M:%S') - $1\e[0m"
    exit 1
}

# Fungsi untuk menampilkan pesan sukses
success_msg() {
    echo -e "\e[32m[SUCCESS] $(date '+%Y-%m-%d %H:%M:%S') - $1\e[0m"
}

# Fungsi untuk menampilkan pesan info
info_msg() {
    echo -e "\e[34m[INFO] $(date '+%Y-%m-%d %H:%M:%S') - $1\e[0m"
}

# Banner
echo "================================================================="
echo "      INSTALASI SERVER MONITORING (PENYIMPANAN BACKUP)           "
echo "================================================================="
echo ""

# Verifikasi bahwa script dijalankan sebagai root
if [ "$(id -u)" -ne 0 ]; then
    error_exit "Script ini harus dijalankan sebagai root."
fi

# Periksa apakah git dan curl terinstall
REQUIRED_MON_CMDS=("git" "curl")
for cmd_mon in "${REQUIRED_MON_CMDS[@]}"; do
    if ! command -v "$cmd_mon" &> /dev/null; then
        info_msg "$cmd_mon tidak ditemukan. Mencoba menginstal..."
        apt-get update -y >/dev/null 2>&1 || warning_msg "Gagal apt-get update, proses instalasi dilanjutkan."
        apt-get install -y "$cmd_mon" || error_exit "Gagal menginstal $cmd_mon."
        success_msg "$cmd_mon berhasil diinstal."
    else
        info_msg "$cmd_mon sudah terinstal."
    fi
done


# Tentukan direktori untuk menyimpan backup
info_msg "Menentukan direktori untuk menyimpan backup Git dan arsip dinamis..."
read -r -p "Masukkan path direktori utama backup (default: /var/backup/web_backups): " MAIN_BACKUP_DIR
MAIN_BACKUP_DIR=${MAIN_BACKUP_DIR:-/var/backup/web_backups}

# Path untuk backup Git (repositori bare)
GIT_BACKUP_SUBDIR="git_repo" # Nama subdirektori untuk Git
ACTUAL_GIT_BACKUP_PATH="$MAIN_BACKUP_DIR/$GIT_BACKUP_SUBDIR"

# Path untuk backup file dinamis (arsip .tar.gz)
DYNAMIC_BACKUP_SUBDIR="dynamic_archives" # Nama subdirektori untuk arsip dinamis
ACTUAL_DYNAMIC_BACKUP_PATH="$MAIN_BACKUP_DIR/$DYNAMIC_BACKUP_SUBDIR"


# Buat direktori backup jika belum ada
if [ ! -d "$ACTUAL_GIT_BACKUP_PATH" ]; then
    info_msg "Membuat direktori backup Git: $ACTUAL_GIT_BACKUP_PATH"
    mkdir -p "$ACTUAL_GIT_BACKUP_PATH" || error_exit "Gagal membuat direktori $ACTUAL_GIT_BACKUP_PATH"
fi
if [ ! -d "$ACTUAL_DYNAMIC_BACKUP_PATH" ]; then
    info_msg "Membuat direktori backup dinamis: $ACTUAL_DYNAMIC_BACKUP_PATH"
    mkdir -p "$ACTUAL_DYNAMIC_BACKUP_PATH" || error_exit "Gagal membuat direktori $ACTUAL_DYNAMIC_BACKUP_PATH"
fi

# Membuat pengguna khusus untuk backup
echo ""
info_msg "Pengaturan Pengguna Khusus untuk Menerima Backup"
echo "----------------------------------------------------"
read -r -p "Apakah Anda ingin membuat pengguna sistem khusus untuk menerima backup via SSH? (y/n, default: y): " CREATE_USER
CREATE_USER=${CREATE_USER:-y}

BACKUP_USER="" # Akan diisi jika CREATE_USER=y

if [[ "$CREATE_USER" == "y" || "$CREATE_USER" == "Y" ]]; then
    read -r -p "Masukkan nama pengguna untuk backup (default: webbackupuser): " INPUT_BACKUP_USER
    BACKUP_USER=${INPUT_BACKUP_USER:-webbackupuser}
    
    if id "$BACKUP_USER" &>/dev/null; then
        info_msg "Pengguna '$BACKUP_USER' sudah ada."
    else
        info_msg "Membuat pengguna '$BACKUP_USER'..."
        # -r untuk system user, -m untuk create home, -s /usr/sbin/nologin atau /bin/bash jika perlu login
        # Untuk Git dan rsync, /usr/sbin/nologin atau /bin/git-shell lebih aman jika hanya untuk itu.
        # Jika menggunakan /bin/bash, pastikan keamanan home directory.
        useradd -r -m -s /bin/bash "$BACKUP_USER" -c "Web Backup Receiver User" || error_exit "Gagal membuat pengguna '$BACKUP_USER'"
        info_msg "Pengguna '$BACKUP_USER' berhasil dibuat. Harap atur password jika diperlukan (misalnya untuk login manual pertama kali)."
        # Umumnya untuk SSH key auth, password tidak wajib diset jika login password dinonaktifkan.
        # echo "Harap atur password untuk pengguna $BACKUP_USER:"
        # passwd "$BACKUP_USER" || warning_msg "Gagal mengatur password untuk pengguna $BACKUP_USER. Anda bisa mengaturnya manual."
    fi
    
    info_msg "Mengatur kepemilikan direktori backup untuk pengguna '$BACKUP_USER'..."
    chown -R "$BACKUP_USER:$BACKUP_USER" "$MAIN_BACKUP_DIR" || warning_msg "Gagal mengubah kepemilikan $MAIN_BACKUP_DIR"
    chmod -R u=rwx,g=,o= "$MAIN_BACKUP_DIR" # Hanya user pemilik yang punya akses penuh. Grup/other tidak ada.

    # Inisialisasi repository Git bare
    info_msg "Menginisialisasi repository Git bare di '$ACTUAL_GIT_BACKUP_PATH'..."
    if [ -d "$ACTUAL_GIT_BACKUP_PATH/.git" ] || [ "$(ls -A "$ACTUAL_GIT_BACKUP_PATH")" ]; then # Cek jika sudah ada .git atau tidak kosong
        read -r -p "Direktori '$ACTUAL_GIT_BACKUP_PATH' sudah ada isinya atau tampak seperti repo. Inisialisasi ulang? (Data lama di path ini akan hilang jika ya) (y/N): " REINIT_BARE_GIT
        REINIT_BARE_GIT=${REINIT_BARE_GIT:-N}
        if [[ "$REINIT_BARE_GIT" == "y" || "$REINIT_BARE_GIT" == "Y" ]]; then
            rm -rf "${ACTUAL_GIT_BACKUP_PATH:?}/"* # Hati-hati dengan rm -rf
            # Jalankan sebagai pengguna backup untuk kepemilikan yang benar
            sudo -u "$BACKUP_USER" git init --bare "$ACTUAL_GIT_BACKUP_PATH" || error_exit "Gagal menginisialisasi ulang repository Git bare."
            success_msg "Repository Git bare berhasil diinisialisasi ulang."
        else
            info_msg "Inisialisasi Git bare dilewati."
        fi
    else
        sudo -u "$BACKUP_USER" git init --bare "$ACTUAL_GIT_BACKUP_PATH" || error_exit "Gagal menginisialisasi repository Git bare."
        success_msg "Repository Git bare berhasil diinisialisasi."
    fi
    
    # Mengatur SSH untuk pengguna backup
    USER_SSH_DIR="/home/$BACKUP_USER/.ssh"
    info_msg "Memastikan direktori SSH '$USER_SSH_DIR' dan 'authorized_keys' ada untuk pengguna '$BACKUP_USER'..."
    sudo -u "$BACKUP_USER" mkdir -p "$USER_SSH_DIR"
    sudo -u "$BACKUP_USER" touch "$USER_SSH_DIR/authorized_keys"
    sudo -u "$BACKUP_USER" chmod 700 "$USER_SSH_DIR"
    sudo -u "$BACKUP_USER" chmod 600 "$USER_SSH_DIR/authorized_keys"
    success_msg "Setup direktori SSH untuk '$BACKUP_USER' selesai."
    
    echo ""
    info_msg "--- INSTRUKSI PENTING UNTUK SERVER WEB ---"
    echo "Untuk mengizinkan server web melakukan push backup ke server monitoring ini:"
    echo "1. Di SERVER WEB, pastikan Anda memiliki SSH key pair untuk user root (atau user yang menjalankan backup)."
    echo "   Kunci publiknya (biasanya di '/root/.ssh/id_rsa_web_backup.pub') perlu disalin."
    echo "2. Di SERVER MONITORING INI, tambahkan isi kunci publik tersebut ke dalam file:"
    echo "   $USER_SSH_DIR/authorized_keys"
    echo "3. Pastikan pengguna '$BACKUP_USER' adalah pemilik file tersebut dan memiliki izin yang benar (chmod 600)."
    echo "--------------------------------------------"

else # Jika tidak membuat pengguna khusus, backup akan diterima oleh root (kurang direkomendasikan)
    BACKUP_USER="root" # Backup akan menggunakan root jika tidak ada user khusus
    info_msg "PERINGATAN: Tidak ada pengguna khusus yang dibuat. Backup akan diterima sebagai pengguna 'root'. Ini kurang aman."
    info_msg "Pastikan direktori '$MAIN_BACKUP_DIR' dapat ditulis oleh root."
    chown -R "root:root" "$MAIN_BACKUP_DIR"
    chmod -R u=rwx,g=,o= "$MAIN_BACKUP_DIR"

    info_msg "Menginisialisasi repository Git bare di '$ACTUAL_GIT_BACKUP_PATH' sebagai root..."
    if [ -d "$ACTUAL_GIT_BACKUP_PATH/.git" ] || [ "$(ls -A "$ACTUAL_GIT_BACKUP_PATH")" ]; then
         read -r -p "Direktori '$ACTUAL_GIT_BACKUP_PATH' sudah ada isinya atau tampak seperti repo. Inisialisasi ulang? (Data lama di path ini akan hilang jika ya) (y/N): " REINIT_BARE_GIT
        REINIT_BARE_GIT=${REINIT_BARE_GIT:-N}
        if [[ "$REINIT_BARE_GIT" == "y" || "$REINIT_BARE_GIT" == "Y" ]]; then
            rm -rf "${ACTUAL_GIT_BACKUP_PATH:?}/"*
            git init --bare "$ACTUAL_GIT_BACKUP_PATH" || error_exit "Gagal menginisialisasi ulang repository Git bare."
            success_msg "Repository Git bare berhasil diinisialisasi ulang."
        else
            info_msg "Inisialisasi Git bare dilewati."
        fi
    else
        git init --bare "$ACTUAL_GIT_BACKUP_PATH" || error_exit "Gagal menginisialisasi repository Git bare."
        success_msg "Repository Git bare berhasil diinisialisasi."
    fi
    info_msg "SSH key dari server web perlu ditambahkan ke '/root/.ssh/authorized_keys' di server monitoring ini."
fi


# Konfigurasi Monitoring Server Ini Sendiri (Opsional)
echo ""
info_msg "Konfigurasi Monitoring untuk Server Backup Ini Sendiri (Opsional)"
echo "-------------------------------------------------------------------"
read -r -p "Apakah Anda ingin menginstal Wazuh Agent untuk memonitor server backup ini sendiri? (y/n, default: n): " INSTALL_WAZUH_AGENT_LOCAL
INSTALL_WAZUH_AGENT_LOCAL=${INSTALL_WAZUH_AGENT_LOCAL:-n}

if [[ "$INSTALL_WAZUH_AGENT_LOCAL" == "y" || "$INSTALL_WAZUH_AGENT_LOCAL" == "Y" ]]; then
    info_msg "Memulai instalasi Wazuh Agent untuk server backup ini..."
    
    if ! command -v apt-key &> /dev/null || ! command -v tee &> /dev/null ; then
        apt-get install -y gnupg apt-transport-https || warning_msg "Gagal install gnupg/apt-transport-https, mungkin diperlukan untuk repo Wazuh."
    fi

    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
    
    apt-get update -y || warning_msg "Gagal apt-get update setelah menambah repo Wazuh."
    apt-get install -y wazuh-agent || error_exit "Gagal menginstal Wazuh Agent."
    
    read -r -p "Masukkan alamat IP Wazuh Manager untuk agent ini: " WAZUH_MANAGER_IP_FOR_AGENT
    while [[ -z "$WAZUH_MANAGER_IP_FOR_AGENT" ]]; do
        read -r -p "Alamat IP Wazuh Manager tidak boleh kosong. Masukkan IP: " WAZUH_MANAGER_IP_FOR_AGENT
    done
    
    # Konfigurasi Wazuh Agent (ossec.conf)
    # Menggunakan variabel WAZUH_MANAGER (bukan MANAGER_IP) di ossec.conf modern
    sed -i "s|<address>MANAGER_IP</address>|<address>$WAZUH_MANAGER_IP_FOR_AGENT</address>|g" /var/ossec/etc/ossec.conf
    
    systemctl daemon-reload
    systemctl enable wazuh-agent
    systemctl restart wazuh-agent # Restart untuk mengambil konfigurasi baru
    
    success_msg "Wazuh Agent berhasil diinstal dan dikonfigurasi untuk memonitor server backup ini."
    info_msg "Pastikan untuk mendaftarkan agent ini di Wazuh Manager."
else
    info_msg "Instalasi Wazuh Agent untuk server backup ini dilewati."
fi

# Konfigurasi Git Hooks untuk Notifikasi (opsional, jika MAIN_BACKUP_DIR dimiliki oleh user yang bisa kirim email)
# ... (Bagian ini bisa tetap ada, pastikan path hook ($ACTUAL_GIT_BACKUP_PATH/hooks) dan kepemilikannya sesuai)
# ... Jika BACKUP_USER dibuat, hook harus dimiliki oleh BACKUP_USER dan bisa menjalankan 'mail'
echo ""
info_msg "Konfigurasi Git Hook untuk Notifikasi Email (Opsional)"
echo "---------------------------------------------------------"
read -r -p "Apakah Anda ingin mengatur notifikasi email setiap kali backup Git diterima? (y/n, default: n): " SETUP_NOTIFICATION
SETUP_NOTIFICATION=${SETUP_NOTIFICATION:-n}

if [[ "$SETUP_NOTIFICATION" == "y" || "$SETUP_NOTIFICATION" == "Y" ]]; then
    if ! command -v mail &> /dev/null; then
        info_msg "Command 'mail' (mailutils) tidak ditemukan. Menginstal..."
        apt-get install -y mailutils || error_exit "Gagal menginstal mailutils. Notifikasi email tidak dapat diatur."
    fi

    if command -v mail &> /dev/null; then
        read -r -p "Masukkan alamat email untuk notifikasi: " NOTIFY_EMAIL
        while [[ -z "$NOTIFY_EMAIL" ]]; do
            read -r -p "Alamat email tidak boleh kosong. Masukkan alamat email: " NOTIFY_EMAIL
        done
        
        HOOK_DIR="$ACTUAL_GIT_BACKUP_PATH/hooks"
        HOOK_FILE="$HOOK_DIR/post-receive"

        info_msg "Membuat direktori hook $HOOK_DIR jika belum ada..."
        # Jika user khusus dibuat, buat direktori sebagai user tersebut
        if [[ "$CREATE_USER" == "y" || "$CREATE_USER" == "Y" ]] && id "$BACKUP_USER" &>/dev/null; then
            sudo -u "$BACKUP_USER" mkdir -p "$HOOK_DIR"
        else # Jika root atau user tidak valid
            mkdir -p "$HOOK_DIR"
        fi

        info_msg "Membuat skrip post-receive hook di $HOOK_FILE..."
        cat > "$HOOK_FILE" << EOF_HOOK
#!/bin/bash
# Git hook untuk mengirim notifikasi email saat menerima backup baru

REPO_NAME="\$(basename "\$(pwd)")" # Seharusnya nama direktori .git nya
COMMIT_INFO=\$(git log -1 --pretty=format:"%h - %an, %ar : %s")
SERVER_HOSTNAME=\$(hostname -f 2>/dev/null || hostname)
TIMESTAMP=\$(date +"%Y-%m-%d %H:%M:%S")

mail -s "Backup GIT Baru Diterima di \$SERVER_HOSTNAME untuk \$REPO_NAME" "$NOTIFY_EMAIL" << EOM_MAIL
Backup Git baru telah diterima di server monitoring: \$SERVER_HOSTNAME

Repository Path: \$(pwd)
Timestamp: \$TIMESTAMP
Commit Terakhir: \$COMMIT_INFO

Pesan ini dikirim otomatis dari hook post-receive.
EOM_MAIL
EOF_HOOK

        chmod +x "$HOOK_FILE"
        if [[ "$CREATE_USER" == "y" || "$CREATE_USER" == "Y" ]] && id "$BACKUP_USER" &>/dev/null; then
            chown "$BACKUP_USER:$BACKUP_USER" "$HOOK_FILE"
            info_msg "Kepemilikan hook diatur ke $BACKUP_USER."
        fi
        success_msg "Notifikasi email untuk backup Git baru telah dikonfigurasi di $HOOK_FILE."
        info_msg "Pastikan MTA (seperti Postfix atau ssmtp) terkonfigurasi di server ini agar perintah 'mail' berfungsi."
    else
        warning_msg "Gagal menginstal atau menemukan 'mail'. Notifikasi email dilewati."
    fi
fi


# Monitoring disk space untuk MAIN_BACKUP_DIR (opsional)
# ... (Bagian ini bisa tetap ada, pastikan path $MAIN_BACKUP_DIR dan user untuk cron sesuai)
# ... Cron job akan berjalan sebagai root jika ditambahkan ke crontab root.
echo ""
info_msg "Monitoring Disk Space untuk Direktori Backup (Opsional)"
echo "-----------------------------------------------------------"
read -r -p "Apakah Anda ingin mengatur monitoring disk space untuk '$MAIN_BACKUP_DIR'? (y/n, default: y): " SETUP_DISK_MONITORING
SETUP_DISK_MONITORING=${SETUP_DISK_MONITORING:-y}

if [[ "$SETUP_DISK_MONITORING" == "y" || "$SETUP_DISK_MONITORING" == "Y" ]]; then
    if ! command -v mail &> /dev/null && ! command -v mailx &> /dev/null ; then # mailx adalah alternatif
        info_msg "Command 'mail' atau 'mailx' tidak ditemukan. Menginstal mailutils..."
        apt-get install -y mailutils || error_exit "Gagal menginstal mailutils. Monitoring disk tidak dapat mengirim email."
    fi

    if command -v mail &> /dev/null || command -v mailx &> /dev/null ; then
        MONITOR_SCRIPT_PATH="/usr/local/bin/monitor_backup_disk_space.sh"
        info_msg "Membuat skrip monitoring disk di $MONITOR_SCRIPT_PATH..."

        cat > "$MONITOR_SCRIPT_PATH" << EOF_DISK_MON
#!/bin/bash
# Skrip untuk memonitor penggunaan disk direktori backup

TARGET_BACKUP_DIR="\$1"
USAGE_THRESHOLD="\$2" # Persentase, misal 80
EMAIL_RECIPIENT="\$3"
SERVER_HOSTNAME=\$(hostname -f 2>/dev/null || hostname)
LOG_FILE="/var/log/backup_disk_monitor.log"
MAIL_COMMAND=\$(command -v mail || command -v mailx)

if [ -z "\$MAIL_COMMAND" ]; then
    echo "[\$(date)] Error: Perintah mail/mailx tidak ditemukan." >> "\$LOG_FILE"
    exit 1
fi

if [ ! -d "\$TARGET_BACKUP_DIR" ]; then
    echo "[\$(date)] Error: Direktori backup '\$TARGET_BACKUP_DIR' tidak ditemukan." >> "\$LOG_FILE"
    exit 1
fi

CURRENT_USAGE=\$(df "\$TARGET_BACKUP_DIR" | awk 'NR==2 {print \$5}' | sed 's/%//')

if [ -z "\$CURRENT_USAGE" ]; then
    echo "[\$(date)] Error: Tidak dapat mengambil info penggunaan disk untuk '\$TARGET_BACKUP_DIR'." >> "\$LOG_FILE"
    exit 1
fi

if [ "\$CURRENT_USAGE" -gt "\$USAGE_THRESHOLD" ]; then
    SUBJECT="[PERINGATAN] Disk Backup di \$SERVER_HOSTNAME Hampir Penuh (\$CURRENT_USAGE%)"
    MESSAGE="Penggunaan disk pada direktori backup '\$TARGET_BACKUP_DIR' di server \$SERVER_HOSTNAME telah mencapai \$CURRENT_USAGE% (Threshold: \$USAGE_THRESHOLD%).\n\nDetail Penggunaan Disk:\n\$(df -h "\$TARGET_BACKUP_DIR")\n\nHarap segera periksa dan kosongkan ruang jika perlu."
    
    echo -e "\$MESSAGE" | \$MAIL_COMMAND -s "\$SUBJECT" "\$EMAIL_RECIPIENT"
    echo "[\$(date)] Peringatan Terkirim: Penggunaan disk \$CURRENT_USAGE% melebihi threshold \$USAGE_THRESHOLD% untuk '\$TARGET_BACKUP_DIR'." >> "\$LOG_FILE"
else
    echo "[\$(date)] Info: Penggunaan disk \$CURRENT_USAGE% untuk '\$TARGET_BACKUP_DIR' masih di bawah threshold \$USAGE_THRESHOLD%." >> "\$LOG_FILE"
fi
exit 0
EOF_DISK_MON
        chmod +x "$MONITOR_SCRIPT_PATH"
        success_msg "Skrip monitoring disk $MONITOR_SCRIPT_PATH berhasil dibuat."

        read -r -p "Masukkan threshold penggunaan disk dalam persen (misal 80, default: 80): " DISK_THRESHOLD_INPUT
        DISK_THRESHOLD_INPUT=${DISK_THRESHOLD_INPUT:-80}
        read -r -p "Masukkan alamat email untuk notifikasi disk space: " DISK_EMAIL_INPUT
        while [[ -z "$DISK_EMAIL_INPUT" ]]; do
            read -r -p "Alamat email tidak boleh kosong. Masukkan alamat email: " DISK_EMAIL_INPUT
        done
        
        CRON_DISK_MON_ENTRY="0 7 * * * $MONITOR_SCRIPT_PATH \"$MAIN_BACKUP_DIR\" \"$DISK_THRESHOLD_INPUT\" \"$DISK_EMAIL_INPUT\""
        
        # Tambahkan ke crontab root
        (crontab -l 2>/dev/null | grep -vF "$MONITOR_SCRIPT_PATH"; echo "$CRON_DISK_MON_ENTRY") | crontab -
        success_msg "Monitoring disk space untuk direktori backup '$MAIN_BACKUP_DIR' telah diatur via cron."
        info_msg "Log monitoring disk akan ada di /var/log/backup_disk_monitor.log"
    else
        warning_msg "Gagal menginstal atau menemukan 'mail/mailx'. Monitoring disk space dilewati."
    fi
fi


SERVER_IP_ADDRESS=$(hostname -I | awk '{print $1}') # Ambil IP utama

echo ""
echo "================================================================="
echo "      INSTALASI SERVER MONITORING BERHASIL DISELESAIKAN         "
echo "================================================================="
echo ""
echo "Informasi Penting untuk Konfigurasi Server Web:"
echo "----------------------------------------------"
echo "IP Server Monitoring Ini: ${SERVER_IP_ADDRESS:-Mohon periksa manual}"
echo "Pengguna SSH untuk Backup: $BACKUP_USER"
echo "Path Tujuan Backup Git: $ACTUAL_GIT_BACKUP_PATH"
echo "Path Tujuan Backup Dinamis (arsip): $ACTUAL_DYNAMIC_BACKUP_PATH"
echo ""
echo "Contoh Perintah di Server Web untuk Menambahkan Remote Git:"
echo "   git remote add monitoring $BACKUP_USER@${SERVER_IP_ADDRESS:-<IP_SERVER_MONITORING>}:$ACTUAL_GIT_BACKUP_PATH"
echo ""
echo "CATATAN PENTING:"
echo "- Format URL Git SSH yang disarankan: '$BACKUP_USER@<IP_SERVER_MONITORING>:$ACTUAL_GIT_BACKUP_PATH' (gunakan path absolut)."
echo "- Pastikan kunci SSH publik dari server web (user root atau yang menjalankan backup) telah ditambahkan ke:"
echo "  '/home/$BACKUP_USER/.ssh/authorized_keys' (jika $BACKUP_USER dibuat) atau '/root/.ssh/authorized_keys' (jika tidak ada user khusus) di server monitoring ini."
echo "- Pastikan direktori '$ACTUAL_DYNAMIC_BACKUP_PATH' dapat ditulis oleh '$BACKUP_USER' (atau root) melalui rsync/scp."
echo ""
echo "Server monitoring ini sekarang siap menerima backup."
echo "================================================================="
