#!/bin/bash

# ==============================================================================
# Skrip Otomatisasi Instalasi MISP dan Pengambilan API Key
# Deskripsi:
# Skrip ini memeriksa apakah Docker dan Docker-Compose terinstal.
# Kemudian, memeriksa apakah kontainer MISP sudah berjalan.
# - Jika tidak berjalan: Mengunduh file docker-compose resmi MISP,
#   menjalankannya, dan menunggu hingga MISP siap.
# - Jika sudah berjalan: Melewatkan instalasi.
# Terakhir, membuat pengguna API baru dan menampilkan kuncinya.
# ==============================================================================

# Keluar segera jika ada perintah yang gagal
set -e
set -o pipefail

# --- Konfigurasi (Sesuaikan jika perlu) ---
# Direktori instalasi MISP
MISP_INSTALL_DIR="/opt/misp-docker"
# URL file docker-compose resmi MISP
MISP_DOCKER_COMPOSE_URL="https://raw.githubusercontent.com/misp/misp-docker/main/docker-compose.yml"

# Detail untuk pengguna API yang akan dibuat
# Anda bisa mengubah ini sesuai kebutuhan
ORG_NAME="Wazuh-IR-Automation"
USER_EMAIL_FOR_KEY="wazuh-automation@localhost.local"
USER_COMMENT="API key for Wazuh Active Response integration"

# --- Variabel Warna untuk Output ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# --- Fungsi ---

# Fungsi untuk memeriksa dependensi yang diperlukan
check_dependencies() {
    echo -e "${YELLOW}Checking dependencies...${NC}"
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}Error: 'docker' is not installed. Please install Docker first.${NC}"
        exit 1
    fi
    if ! command -v docker-compose &> /dev/null; then
        echo -e "${RED}Error: 'docker-compose' is not installed. Please install Docker Compose first.${NC}"
        exit 1
    fi
    echo -e "${GREEN}Dependencies are satisfied.${NC}"
}

# Fungsi untuk menunggu MISP siap menerima koneksi
wait_for_misp() {
    echo -e "${YELLOW}Waiting for MISP to become available... This may take several minutes.${NC}"
    until curl --output /dev/null --silent --head --fail --insecure https://localhost; do
        printf '.'
        sleep 5
    done
    echo -e "\n${GREEN}MISP is up and running!${NC}"
}

# --- Logika Utama Skrip ---

echo "========================================="
echo "   MISP Installation & API Key Setup   "
echo "========================================="

check_dependencies

# Periksa apakah kontainer MISP sudah berjalan
# Kita periksa kontainer dengan nama yang mengandung 'misp-server'
MISP_CONTAINER_ID=$(docker ps -q --filter "name=misp-server")

if [ -z "$MISP_CONTAINER_ID" ]; then
    echo -e "${YELLOW}MISP container not found. Starting installation process...${NC}"

    # 1. Buat direktori instalasi
    echo "Creating installation directory at ${MISP_INSTALL_DIR}..."
    sudo mkdir -p "$MISP_INSTALL_DIR"
    sudo chown $USER:$USER "$MISP_INSTALL_DIR"
    cd "$MISP_INSTALL_DIR"

    # 2. Unduh file docker-compose.yml
    echo "Downloading latest misp-docker docker-compose.yml..."
    curl -o docker-compose.yml "$MISP_DOCKER_COMPOSE_URL"

    # 3. Jalankan MISP menggunakan docker-compose
    echo "Starting MISP containers in detached mode (-d)..."
    sudo docker-compose up -d

    # 4. Tunggu hingga MISP benar-benar siap
    wait_for_misp

    echo -e "${GREEN}MISP installation completed successfully.${NC}"
else
    echo -e "${GREEN}MISP is already installed and running.${NC}"
    # Pastikan kita berada di direktori yang benar untuk perintah exec
    cd "$MISP_INSTALL_DIR"
fi

# --- Pengambilan API Key ---
echo -e "${YELLOW}Attempting to create/retrieve API key for user '${USER_EMAIL_FOR_KEY}'...${NC}"

# Dapatkan email admin default dari dalam kontainer
# Biasanya admin@admin.test pada instalasi awal
ADMIN_EMAIL=$(sudo docker-compose exec -T misp-server cat /var/www/MISP/app/Config/config.php | grep "'email' =>" | head -1 | sed "s/.*'email' => '\([^']*\)'.*/\1/")

if [ -z "$ADMIN_EMAIL" ]; then
    echo -e "${RED}Could not automatically determine admin email. Defaulting to 'admin@admin.test'.${NC}"
    ADMIN_EMAIL="admin@admin.test"
fi

echo "Using admin email: ${ADMIN_EMAIL}"

# Gunakan perintah 'cake' di dalam kontainer untuk membuat pengguna dan mendapatkan kuncinya.
# Perintah ini akan membuat pengguna jika belum ada, atau hanya menampilkan kunci jika sudah ada.
API_KEY_OUTPUT=$(sudo docker-compose exec -T misp-server \
    /var/www/MISP/app/Console/cake Admin setApiUser "$ADMIN_EMAIL" "$ORG_NAME" "$USER_EMAIL_FOR_KEY" "$USER_COMMENT")

# Ekstrak kunci API dari output
MISP_KEY=$(echo "$API_KEY_OUTPUT" | grep 'Auth key:' | awk '{print $3}')

if [ -n "$MISP_KEY" ]; then
    echo -e "${GREEN}Successfully retrieved API Key!${NC}"
    echo "------------------------------------------------------------------"
    echo -e "Your MISP API Key is: ${YELLOW}${MISP_KEY}${NC}"
    echo "------------------------------------------------------------------"
    echo "Simpan kunci ini di tempat yang aman. Anda akan membutuhkannya untuk"
    echo "mengkonfigurasi skrip integrasi Wazuh (wazuh-misp.py)."
else
    echo -e "${RED}Error: Failed to retrieve API Key.${NC}"
    echo "Please check the logs using 'sudo docker-compose logs -f' in '${MISP_INSTALL_DIR}'."
    exit 1
fi

exit 0
