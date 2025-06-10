#!/usr/bin/env python3

"""
SOC Containment Script - NIST 800-61 Incident Response Framework
Containment Phase: Isolasi ancaman dan stabilisasi sistem
"""

import os
import sys
import json
import logging
import subprocess
from datetime import datetime
import ipaddress # Untuk validasi IP
import shutil # Untuk operasi file seperti copy
import glob # Untuk mencari file backup saat disable maintenance mode

# Konfigurasi logging
LOG_FILE = "/var/log/wazuh/active-response/containment.log"

try:
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
except OSError as e:
    print(f"Warning: Tidak dapat membuat direktori log {os.path.dirname(LOG_FILE)}. Error: {e}", file=sys.stderr)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('soc_containment')

# Support untuk multiple config path
CONFIG_FILES = ["/etc/soc-config/config.conf", "/etc/web-backup/config.conf"]

class ContainmentManager:
    def __init__(self):
        self.config = self._load_config()
        self.web_dir = self.config.get("WEB_DIR")

        if not self.web_dir or not os.path.isdir(self.web_dir):
            msg = f"WEB_DIR ('{self.web_dir}') tidak valid atau tidak ditemukan dalam konfigurasi."
            logger.error(msg)
            raise ValueError(msg)

        self.maintenance_page_filename = "maintenance.html"
        self.index_filename = "index.html"

        self.maintenance_page_source_path = os.path.join(self.web_dir, self.maintenance_page_filename)
        self.live_index_path = os.path.join(self.web_dir, self.index_filename)

        self.blocked_ips_file = "/var/log/wazuh/blocked_ips.txt"
        try:
            os.makedirs(os.path.dirname(self.blocked_ips_file), exist_ok=True)
        except OSError as e:
            logger.warning(f"Tidak dapat membuat direktori untuk blocked_ips_file ({self.blocked_ips_file}): {e}")

    def _load_config(self):
        """Memuat konfigurasi dari file."""
        config = {}
        config_file = None
        
        # Cari config file yang ada
        for cf in CONFIG_FILES:
            if os.path.exists(cf):
                config_file = cf
                break
        
        if not config_file:
            logger.error(f"File konfigurasi tidak ditemukan di: {', '.join(CONFIG_FILES)}")
            return config

        try:
            with open(config_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and '=' in line and not line.startswith('#'):
                        line_content = line.split('#', 1)[0].strip()
                        if not line_content:
                            continue
                        key, value = line_content.split('=', 1)
                        key = key.strip()
                        value = value.strip().strip('"\'')
                        config[key] = value
            logger.info(f"Konfigurasi dimuat dari: {config_file}")
        except Exception as e:
            logger.error(f"Gagal membaca file konfigurasi {config_file}: {e}")
        return config

    def _is_ip_blocked(self, ip):
        """Memeriksa apakah IP sudah diblokir menggunakan iptables."""
        try:
            result = subprocess.run(['iptables', '-C', 'INPUT', '-s', ip, '-j', 'DROP'],
                                 capture_output=True, check=False)
            return result.returncode == 0
        except FileNotFoundError:
            logger.error("Perintah 'iptables' tidak ditemukan.")
            return False
        except Exception as e:
            logger.error(f"Error saat memeriksa status blokir IP {ip} dengan iptables: {e}")
            return False

    def block_ip(self, ip):
        """Memblokir IP menggunakan iptables dan mencatatnya."""
        logger.info(f"Mencoba memblokir IP: {ip}")
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            logger.error(f"Format IP tidak valid: {ip}")
            return False

        if self._is_ip_blocked(ip):
            logger.info(f"IP {ip} sudah diblokir sebelumnya.")
            return True

        try:
            subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], 
                          check=True, capture_output=True, text=True)
            logger.info(f"IP {ip} berhasil diblokir menggunakan iptables.")

            try:
                blocked_ips = set()
                if os.path.exists(self.blocked_ips_file):
                    with open(self.blocked_ips_file, 'r') as f:
                        for line_ip in f:
                            blocked_ips.add(line_ip.strip())
                
                if ip not in blocked_ips:
                    with open(self.blocked_ips_file, 'a') as f:
                        f.write(f"{ip}\n")
                    logger.info(f"IP {ip} ditambahkan ke {self.blocked_ips_file}")
                else:
                    logger.info(f"IP {ip} sudah ada di {self.blocked_ips_file}")

            except IOError as e:
                logger.error(f"Gagal menulis ke file blocked_ips {self.blocked_ips_file}: {e}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Gagal memblokir IP {ip} menggunakan iptables: {e}. stderr: {e.stderr}")
            return False
        except FileNotFoundError:
            logger.error("Perintah 'iptables' tidak ditemukan. Tidak dapat memblokir IP.")
            return False

    def enable_maintenance_mode(self):
        """Mengaktifkan mode maintenance dengan mengganti file index."""
        logger.info(f"Mencoba mengaktifkan mode maintenance untuk direktori: {self.web_dir}")

        if not os.path.exists(self.maintenance_page_source_path):
            logger.error(f"File sumber halaman maintenance '{self.maintenance_page_source_path}' tidak ditemukan.")
            logger.error("Pastikan file maintenance.html sudah di-deploy ke direktori web oleh skrip instalasi.")
            return False

        try:
            if os.path.exists(self.live_index_path):
                # Membuat nama backup yang unik dengan timestamp
                backup_live_index_path = os.path.join(
                    self.web_dir, 
                    f"{self.index_filename}.bak_containment_{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
                )
                shutil.copy2(self.live_index_path, backup_live_index_path)
                logger.info(f"File index utama '{self.live_index_path}' berhasil di-backup ke '{backup_live_index_path}'.")
            else:
                logger.warning(f"File index utama '{self.live_index_path}' tidak ditemukan. Akan tetap menempatkan halaman maintenance.")

            shutil.copy2(self.maintenance_page_source_path, self.live_index_path)
            logger.info(f"Mode maintenance berhasil diaktifkan. '{self.live_index_path}' sekarang menampilkan halaman maintenance.")
            return True
        except Exception as e:
            logger.error(f"Gagal mengaktifkan mode maintenance: {e}", exc_info=True)
            return False

    def disable_maintenance_mode(self):
        """Menonaktifkan mode maintenance dengan mengembalikan index.html dari backup terakhir."""
        logger.info("Mencoba menonaktifkan mode maintenance.")
        
        backup_pattern = os.path.join(self.web_dir, f"{self.index_filename}.bak_containment_*")
        list_of_backups = glob.glob(backup_pattern)
        if not list_of_backups:
            logger.error(f"Tidak ada file backup index dengan pola '{backup_pattern}' ditemukan.")
            return False

        try:
            latest_backup_file = max(list_of_backups, key=os.path.getmtime)
            logger.info(f"Menggunakan file backup index terbaru: {latest_backup_file}")

            shutil.copy2(latest_backup_file, self.live_index_path)
            logger.info(f"Mode maintenance berhasil dinonaktifkan. '{self.live_index_path}' dipulihkan dari '{latest_backup_file}'.")
            return True
        except Exception as e:
            logger.error(f"Gagal menonaktifkan mode maintenance: {e}", exc_info=True)
            return False

    def process_wazuh_alert(self, alert_data_str):
        """Memproses alert dari Wazuh dan mengambil tindakan containment."""
        logger.info("Menerima data alert dari Wazuh untuk containment.")
        try:
            alert = json.loads(alert_data_str)
            logger.debug(f"Data alert yang di-parse: {alert}")
        except json.JSONDecodeError as e:
            logger.error(f"Format data alert Wazuh tidak valid (JSONDecodeError): {e}. Data: {alert_data_str[:200]}...")
            return False

        rule_id = str(alert.get('rule', {}).get('id', ''))
        src_ip = alert.get('data', {}).get('srcip')
        description = alert.get('rule', {}).get('description', 'N/A')

        logger.info(f"Memproses alert Wazuh - Rule ID: {rule_id}, Deskripsi: {description}, Source IP: {src_ip if src_ip else 'N/A'}")

        actions_performed = []

        # Ambil rule IDs dari konfigurasi
        deface_rule_ids = self.config.get("DEFACE_RULE_IDS", "550,554,5501,5502,5503,5504,100001,100002").split(',')
        attack_rule_ids = self.config.get("ATTACK_RULE_IDS", "5710,5712,5715,5760,100003,100004").split(',')
        
        # Normalisasi rule IDs (hapus whitespace)
        deface_rule_ids = [rid.strip() for rid in deface_rule_ids]
        attack_rule_ids = [rid.strip() for rid in attack_rule_ids]

        # Logika containment berdasarkan rule_id
        if rule_id in deface_rule_ids:
            logger.info(f"Terdeteksi rule defacement (ID: {rule_id}). Mengaktifkan mode maintenance...")
            if self.enable_maintenance_mode():
                actions_performed.append("Maintenance mode activated")
                logger.info("Mode maintenance berhasil diaktifkan sebagai respons defacement.")
            else:
                logger.error("Gagal mengaktifkan mode maintenance.")

        if rule_id in attack_rule_ids or rule_id in deface_rule_ids:
            if src_ip:
                logger.info(f"Mencoba memblokir IP penyerang: {src_ip}")
                if self.block_ip(src_ip):
                    actions_performed.append(f"IP {src_ip} blocked")
                    logger.info(f"IP {src_ip} berhasil diblokir.")
                else:
                    logger.error(f"Gagal memblokir IP {src_ip}.")
            else:
                logger.warning("Tidak ada source IP untuk diblokir dalam alert ini.")

        # Log hasil containment
        if actions_performed:
            summary = f"Containment actions completed: {', '.join(actions_performed)}"
            logger.info(summary)
            return True
        else:
            logger.info(f"Tidak ada tindakan containment yang diperlukan untuk rule ID: {rule_id}")
            return False

    def unblock_ip(self, ip):
        """Menghapus blokir IP (untuk testing atau remediation)."""
        logger.info(f"Mencoba menghapus blokir IP: {ip}")
        try:
            subprocess.run(['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'], 
                          check=True, capture_output=True, text=True)
            logger.info(f"IP {ip} berhasil di-unblock dari iptables.")
            
            # Hapus dari file log juga
            if os.path.exists(self.blocked_ips_file):
                with open(self.blocked_ips_file, 'r') as f:
                    lines = f.readlines()
                with open(self.blocked_ips_file, 'w') as f:
                    for line in lines:
                        if line.strip() != ip:
                            f.write(line)
                logger.info(f"IP {ip} dihapus dari {self.blocked_ips_file}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Gagal menghapus blokir IP {ip}: {e}")
            return False


def main():
    """Main function untuk Active Response dari Wazuh."""
    try:
        # Inisialisasi containment manager
        containment = ContainmentManager()
        
        # Cek apakah ada argumen untuk operasi manual
        if len(sys.argv) > 1:
            command = sys.argv[1].lower()
            
            if command == "enable-maintenance":
                success = containment.enable_maintenance_mode()
                sys.exit(0 if success else 1)
                
            elif command == "disable-maintenance":
                success = containment.disable_maintenance_mode()
                sys.exit(0 if success else 1)
                
            elif command == "block-ip" and len(sys.argv) > 2:
                ip = sys.argv[2]
                success = containment.block_ip(ip)
                sys.exit(0 if success else 1)
                
            elif command == "unblock-ip" and len(sys.argv) > 2:
                ip = sys.argv[2]
                success = containment.unblock_ip(ip)
                sys.exit(0 if success else 1)
                
            else:
                logger.error(f"Command tidak dikenali: {command}")
                print("Usage: containment.py [enable-maintenance|disable-maintenance|block-ip <ip>|unblock-ip <ip>]")
                sys.exit(1)
        
        # Mode Wazuh Active Response - baca alert dari stdin
        logger.info("Menunggu data alert dari Wazuh Active Response...")
        
        # Baca input dari stdin (alert data dari Wazuh)
        try:
            alert_data = sys.stdin.read().strip()
            if not alert_data:
                logger.error("Tidak ada data alert yang diterima dari stdin.")
                sys.exit(1)
                
            logger.info(f"Data alert diterima: {alert_data[:100]}...")
            
            # Proses alert
            success = containment.process_wazuh_alert(alert_data)
            sys.exit(0 if success else 1)
            
        except Exception as e:
            logger.error(f"Error membaca alert data dari stdin: {e}")
            sys.exit(1)
            
    except Exception as e:
        logger.error(f"Error dalam main function: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
