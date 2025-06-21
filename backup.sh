#!/bin/bash

# SOC Backup Script - NIST 800-61 Incident Response Framework
# Backup website files ke server monitoring menggunakan Git dan rsync
# --------------------------------------------------------------------

# Fungsi untuk menampilkan pesan error dan keluar
function error_exit {
    echo -e "\e[31m[ERROR] $(date '+%Y-%m-%d %H:%M:%S') - $1\e[0m"
    exit 1
}

# Fungsi untuk menampilkan pesan sukses
function success_msg {
    echo -e "\e[32m[SUCCESS] $(date '+%Y-%m-%d %H:%M:%S') - $1\e[0m"
}

# Fungsi untuk menampilkan pesan info
function info_msg {
    echo -e "\e[34m[INFO] $(date '+%Y-%m-%d %H:%M:%S') - $1\e[0m"
}

# Fungsi untuk menampilkan pesan warning
function warning_msg {
    echo -e "\e[33m[WARNING] $(date '+%Y-%m-%d %H:%M:%S') - $1\e[0m"
}

# Banner
echo "================================================================="
echo "      SOC BACKUP SYSTEM - NIST 800-61 INCIDENT RESPONSE         "
echo "================================================================="
echo ""

# Verifikasi bahwa script dijalankan sebagai root
if [ "$(id -u)" -ne 0 ]; then
    error_exit "Script ini harus dijalankan sebagai root."
fi

# Memuat konfigurasi - support untuk kedua path untuk kompatibilitas
CONFIG_FILE=""
if [ -f "/etc/soc-config/config.conf" ]; then
    CONFIG_FILE="/etc/soc-config/config.conf"
elif [ -f "/etc/web-backup/config.conf" ]; then
    CONFIG_FILE="/etc/web-backup/config.conf"
else
    error_exit "File konfigurasi tidak ditemukan di /etc/soc-config/config.conf atau /etc/web-backup/config.conf. Jalankan script instalasi terlebih dahulu."
fi

info_msg "Menggunakan file konfigurasi: $CONFIG_FILE"

# shellcheck source=/dev/null
source "$CONFIG_FILE"

# Verifikasi variabel konfigurasi penting untuk backup
REQUIRED_VARS_BACKUP=("WEB_DIR" "PASSWORD" "MONITOR_USER" "MONITOR_IP" "REMOTE_GIT_BACKUP_PATH" "SSH_IDENTITY_FILE")
for var in "${REQUIRED_VARS_BACKUP[@]}"; do
    if [ -z "${!var+x}" ] || [ -z "${!var}" ]; then
        error_exit "Variabel konfigurasi '$var' tidak ditemukan atau kosong di '$CONFIG_FILE'."
    fi
done

# Support untuk WAZUH_MANAGER_IP jika MONITOR_IP tidak ada
if [ -n "${WAZUH_MANAGER_IP:-}" ]; then
    MONITOR_IP="$WAZUH_MANAGER_IP"
fi

# Verifikasi direktori web server
if [ ! -d "$WEB_DIR" ]; then
    error_exit "Direktori web server '$WEB_DIR' tidak ditemukan!"
fi

# Meminta password untuk verifikasi (kecuali jika dipanggil dari cron job atau automasi)
if [ -t 0 ]; then  # Jika input terminal tersedia (bukan dari cron)
    read -r -sp "Masukkan password backup: " INPUT_PASSWORD
    echo ""
    
    # Membandingkan password yang dimasukkan dengan password yang tersimpan
    INPUT_PASSWORD_B64=$(echo -n "$INPUT_PASSWORD" | base64)
    
    if [ "$INPUT_PASSWORD_B64" != "$PASSWORD" ]; then
        # Fallback jika password di config belum di-base64 (untuk kompatibilitas)
        DECODED_PASSWORD=$(echo "$PASSWORD" | base64 -d 2>/dev/null || echo "$PASSWORD")
        if [ "$INPUT_PASSWORD" != "$DECODED_PASSWORD" ]; then
           error_exit "Password salah!"
        fi
    fi
    info_msg "Password terverifikasi."
fi

# Memulai proses backup GIT
info_msg "Memulai proses backup Git dari '$WEB_DIR'..."

# Masuk ke direktori web server
cd "$WEB_DIR" || error_exit "Gagal masuk ke direktori '$WEB_DIR'"

# Periksa apakah git sudah diinisialisasi
if [ ! -d ".git" ]; then
    error_exit "Repository Git tidak ditemukan di '$WEB_DIR'. Jalankan script instalasi terlebih dahulu."
fi

# Pastikan konfigurasi git lokal sudah diatur
if ! git config --local user.email >/dev/null 2>&1 || ! git config --local user.name >/dev/null 2>&1; then
    warning_msg "Konfigurasi Git user.name atau user.email lokal tidak ditemukan. Mengatur default..."
    git config --local user.name "SOC System"
    git config --local user.email "soc@localhost"
fi

# Cek perubahan pada file
info_msg "Memeriksa perubahan pada file untuk Git..."
CHANGES=$(git status --porcelain)
if [ -n "$CHANGES" ]; then
    info_msg "Ditemukan perubahan file:"
    echo "$CHANGES"
else
    info_msg "Tidak ada perubahan file terdeteksi."
fi

# Menambahkan semua file yang baru atau berubah
info_msg "Menambahkan file yang baru atau berubah ke repository Git..."
git add -A

# Melakukan commit dengan timestamp
TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
COMMIT_MESSAGE="SOC Automated backup: $TIMESTAMP"
info_msg "Melakukan commit Git: $COMMIT_MESSAGE..."

if git commit -m "$COMMIT_MESSAGE"; then
    success_msg "Commit Git berhasil."
    BACKUP_COMMIT_HASH=$(git rev-parse HEAD)
    info_msg "Commit hash: $BACKUP_COMMIT_HASH"
else
    COMMIT_EXIT_CODE=$?
    if [ $COMMIT_EXIT_CODE -eq 1 ]; then
        info_msg "Tidak ada perubahan untuk di-commit ke Git."
    else
        warning_msg "Gagal melakukan commit Git dengan kode exit: $COMMIT_EXIT_CODE"
    fi
fi

# Cek apakah remote 'monitoring' sudah diatur
REMOTE_GIT_URL_EXPECTED="$MONITOR_USER@$MONITOR_IP:$REMOTE_GIT_BACKUP_PATH"
CURRENT_REMOTE_URL=$(git remote get-url monitoring 2>/dev/null || echo "")

if [ "$CURRENT_REMOTE_URL" != "$REMOTE_GIT_URL_EXPECTED" ]; then
    info_msg "Mengatur atau memperbarui remote Git 'monitoring'..."
    git remote rm monitoring 2>/dev/null || true # Hapus jika ada
    git remote add monitoring "$REMOTE_GIT_URL_EXPECTED" || 
        error_exit "Gagal mengatur remote Git 'monitoring'."
    success_msg "Remote Git 'monitoring' berhasil dikonfigurasi."
else
    info_msg "Remote Git 'monitoring' sudah dikonfigurasi dengan benar."
fi

# Periksa apakah remote repository dapat dijangkau
SSH_OPTIONS="-o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=no"
if [ -f "$SSH_IDENTITY_FILE" ]; then
    SSH_OPTIONS="$SSH_OPTIONS -i $SSH_IDENTITY_FILE"
else
    warning_msg "SSH identity file tidak ditemukan: $SSH_IDENTITY_FILE"
fi

info_msg "Memeriksa koneksi SSH ke server monitoring ($MONITOR_IP)..."
if ssh $SSH_OPTIONS "$MONITOR_USER@$MONITOR_IP" exit 2>/dev/null; then
    success_msg "Koneksi SSH ke server monitoring berhasil."
else
    error_exit "Tidak dapat terhubung ke server monitoring '$MONITOR_USER@$MONITOR_IP'. Periksa konfigurasi SSH, kunci, dan pastikan server monitoring aktif serta dapat dijangkau."
fi

# Backup Git ke server monitoring
info_msg "Melakukan push Git ke server monitoring ($MONITOR_IP)..."

export GIT_SSH_COMMAND="ssh $SSH_OPTIONS"
if ! git remote get-url monitoring &>/dev/null; then
    error_exit "Remote Git 'monitoring' tidak ditemukan. Pastikan telah dikonfigurasi."
fi
BRANCH=$(git branch --show-current)

if git push -u monitoring "$BRANCH"; then
    success_msg "Push Git ke server monitoring berhasil (branch $BRANCH)."
else
    error_exit "Gagal melakukan push Git ke server monitoring. Pastikan remote 'monitoring' tersedia dan repo tujuan sudah diinisialisasi sebagai bare repository."
fi


success_msg "Proses backup konten statis (Git) berhasil diselesaikan."
echo ""

# --- PROSES BACKUP FILE DINAMIS ---
info_msg "Memulai proses backup file dinamis..."

if [ "${BACKUP_DYNAMIC:-false}" != "true" ]; then
    info_msg "Backup file dinamis tidak diaktifkan dalam konfigurasi. Melewati."
else
    # Verifikasi variabel yang dibutuhkan untuk backup dinamis
    REQUIRED_VARS_DYNAMIC=("LOCAL_DYNAMIC_STAGING_DIR" "REMOTE_DYNAMIC_BACKUP_PATH")
    MISSING_VAR_DYNAMIC=false
    for var_dyn in "${REQUIRED_VARS_DYNAMIC[@]}"; do
        if [ -z "${!var_dyn+x}" ] || [ -z "${!var_dyn}" ]; then
            warning_msg "Variabel konfigurasi '$var_dyn' untuk backup dinamis tidak ditemukan atau kosong. Melewati backup dinamis."
            MISSING_VAR_DYNAMIC=true
            break
        fi
    done

    if [ "$MISSING_VAR_DYNAMIC" = "false" ]; then
        if [ ! -d "$LOCAL_DYNAMIC_STAGING_DIR" ]; then
            warning_msg "Direktori staging lokal '$LOCAL_DYNAMIC_STAGING_DIR' untuk file dinamis tidak ditemukan. Melewati backup dinamis."
        else
            # Jalankan script backup dinamis
            if command -v /usr/local/bin/soc-backup-dynamic >/dev/null 2>&1; then
                info_msg "Menjalankan backup dinamis..."
                /usr/local/bin/soc-backup-dynamic
            else
                warning_msg "Script soc-backup-dynamic tidak ditemukan. Membuat arsip manual..."
                # Backup manual jika script tidak ada
                if [ -n "${DYNAMIC_DIRS:-}" ]; then
                    cd "$WEB_DIR" || exit 1
                    BACKUP_TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
                    
                    # Parse DYNAMIC_DIRS array dari string bash
                    eval "DIRS_ARRAY=$DYNAMIC_DIRS"
                    for dir in "${DIRS_ARRAY[@]}"; do
                        if [ -d "$dir" ]; then
                            ARCHIVE_NAME="dynamic_${dir}_${BACKUP_TIMESTAMP}.tar.gz"
                            ARCHIVE_PATH="$LOCAL_DYNAMIC_STAGING_DIR/$ARCHIVE_NAME"
                            
                            if tar -czf "$ARCHIVE_PATH" "$dir" 2>/dev/null; then
                                info_msg "Arsip dinamis '$ARCHIVE_NAME' berhasil dibuat."
                            else
                                warning_msg "Gagal membuat arsip untuk direktori '$dir'."
                            fi
                        fi
                    done
                fi
            fi

            # Cek apakah ada file untuk ditransfer
            NUM_ARCHIVES=$(find "$LOCAL_DYNAMIC_STAGING_DIR" -maxdepth 1 -name "*.tar.gz" -type f 2>/dev/null | wc -l)

            if [ "$NUM_ARCHIVES" -eq 0 ]; then
                info_msg "Tidak ada arsip (.tar.gz) ditemukan di direktori staging lokal '$LOCAL_DYNAMIC_STAGING_DIR'."
            else
                info_msg "Ditemukan $NUM_ARCHIVES arsip di '$LOCAL_DYNAMIC_STAGING_DIR'. Memulai transfer..."

                # Pastikan direktori remote untuk backup dinamis ada
                if ssh $SSH_OPTIONS "$MONITOR_USER@$MONITOR_IP" "mkdir -p \"$REMOTE_DYNAMIC_BACKUP_PATH\"" 2>/dev/null; then
                    success_msg "Direktori remote '$REMOTE_DYNAMIC_BACKUP_PATH' siap."
                else
                    error_exit "Gagal membuat atau memastikan direktori remote '$REMOTE_DYNAMIC_BACKUP_PATH' di server monitoring."
                fi

                # Transfer file menggunakan rsync
                if command -v rsync >/dev/null 2>&1; then
                    RSYNC_CMD="rsync -avz --remove-source-files --include='*.tar.gz' --exclude='*' -e \"ssh $SSH_OPTIONS\" \"$LOCAL_DYNAMIC_STAGING_DIR/\" \"$MONITOR_USER@$MONITOR_IP:$REMOTE_DYNAMIC_BACKUP_PATH/\""
                    
                    info_msg "Mentransfer arsip file dinamis dengan rsync..."
                    if eval "$RSYNC_CMD" 2>/dev/null; then
                        success_msg "Transfer arsip dinamis berhasil dengan rsync."
                    else
                        warning_msg "Transfer dengan rsync gagal. Mencoba dengan scp..."
                        # Fallback ke scp
                        for archive_file in "$LOCAL_DYNAMIC_STAGING_DIR"/*.tar.gz; do
                            if [ -f "$archive_file" ]; then
                                if scp $SSH_OPTIONS "$archive_file" "$MONITOR_USER@$MONITOR_IP:$REMOTE_DYNAMIC_BACKUP_PATH/" 2>/dev/null; then
                                    rm -f "$archive_file"
                                    info_msg "Transfer berhasil: $(basename "$archive_file")"
                                else
                                    warning_msg "Gagal transfer: $(basename "$archive_file")"
                                fi
                            fi
                        done
                    fi
                else
                    warning_msg "rsync tidak tersedia. Menggunakan scp..."
                    for archive_file in "$LOCAL_DYNAMIC_STAGING_DIR"/*.tar.gz; do
                        if [ -f "$archive_file" ]; then
                            if scp $SSH_OPTIONS "$archive_file" "$MONITOR_USER@$MONITOR_IP:$REMOTE_DYNAMIC_BACKUP_PATH/" 2>/dev/null; then
                                rm -f "$archive_file"
                                info_msg "Transfer berhasil: $(basename "$archive_file")"
                            else
                                warning_msg "Gagal transfer: $(basename "$archive_file")"
                            fi
                        fi
                    done
                fi
            fi
        fi
    fi
fi

success_msg "Proses backup file dinamis selesai."
echo ""

# --- LOG HASIL BACKUP ---
LOG_FILE="/var/log/soc-backup.log"
echo "$(date '+%Y-%m-%d %H:%M:%S') - Backup completed successfully. Commit: ${BACKUP_COMMIT_HASH:-'N/A'}" >> "$LOG_FILE"

echo "================================================================="
echo "      BACKUP SOC SELESAI                                         "
echo "================================================================="
echo ""
echo "Ringkasan:"
echo "- Direktori Web: $WEB_DIR"
echo "- Server Monitoring: $MONITOR_USER@$MONITOR_IP"
echo "- Remote Git Path: $REMOTE_GIT_BACKUP_PATH"
if [ -n "${BACKUP_COMMIT_HASH:-}" ]; then
    echo "- Git Commit Hash: $BACKUP_COMMIT_HASH"
fi
if [ "${BACKUP_DYNAMIC:-false}" = "true" ]; then
    echo "- Backup Dinamis: Aktif"
    echo "- Remote Dynamic Path: $REMOTE_DYNAMIC_BACKUP_PATH"
fi
echo "- Log File: $LOG_FILE"
echo ""
echo "Backup berhasil diselesaikan pada: $(date)"
echo "================================================================="
