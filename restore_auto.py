#!/usr/bin/env python3

"""
SOC Restore Auto Script - NIST 800-61 Incident Response Framework
Recovery Phase: Restore otomatis sistem dari backup untuk Wazuh Active Response
"""

import os
import sys
import json
import logging
import subprocess
import time
from datetime import datetime
from pathlib import Path

# Konfigurasi logging
LOG_FILE = "/var/log/wazuh/active-response/restore_auto.log"

try:
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
except OSError as e:
    print(f"Warning: Tidak dapat membuat direktori log {os.path.dirname(LOG_FILE)}. Error: {e}", file=sys.stderr)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('soc_restore_auto')

# Support untuk multiple config path
CONFIG_FILES = ["/etc/soc-config/config.conf", "/etc/web-backup/config.conf"]

class AutoRestoreManager:
    def __init__(self):
        self.config = self._load_config()
        
        # Konfigurasi dari file config
        self.web_dir = self.config.get("WEB_DIR", "/var/www/html")
        self.backup_dir = self.config.get("BACKUP_DIR", "/var/soc-backup")
        self.monitoring_user = self.config.get("MONITORING_USER", "soc-backup")
        self.monitoring_server = self.config.get("MONITORING_SERVER", "")
        self.monitoring_password = self.config.get("MONITORING_PASSWORD", "")
        
        # Path backup lokal dan remote
        self.local_backup_path = os.path.join(self.backup_dir, "local")
        self.remote_backup_path = self.config.get("REMOTE_BACKUP_PATH", "/home/soc-backup/backups")
        
        # Konteks alert saat ini
        self.current_alert_context = {}
        
        # Validasi konfigurasi
        self._validate_config()

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
                        config[key.strip()] = value.strip().strip('"\'')
            logger.info(f"Konfigurasi dimuat dari: {config_file}")
        except Exception as e:
            logger.error(f"Gagal membaca file konfigurasi {config_file}: {e}")
        return config

    def _validate_config(self):
        """Validasi konfigurasi yang diperlukan."""
        required_configs = ["WEB_DIR", "BACKUP_DIR"]
        missing_configs = []
        
        for config_key in required_configs:
            if not self.config.get(config_key):
                missing_configs.append(config_key)
        
        if missing_configs:
            logger.error(f"Konfigurasi yang diperlukan tidak ditemukan: {', '.join(missing_configs)}")
            raise ValueError(f"Konfigurasi tidak lengkap: {', '.join(missing_configs)}")
        
        # Validasi direktori
        if not os.path.isdir(self.web_dir):
            logger.error(f"Direktori web tidak ditemukan: {self.web_dir}")
            raise ValueError(f"Direktori web tidak valid: {self.web_dir}")

    def _run_command(self, command, timeout=300):
        """Menjalankan command dengan timeout."""
        try:
            logger.info(f"Menjalankan command: {command}")
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            if result.returncode == 0:
                logger.info(f"Command berhasil: {command}")
                if result.stdout:
                    logger.debug(f"Output: {result.stdout}")
                return True, result.stdout
            else:
                logger.error(f"Command gagal: {command}")
                logger.error(f"Error: {result.stderr}")
                return False, result.stderr
                
        except subprocess.TimeoutExpired:
            logger.error(f"Command timeout setelah {timeout} detik: {command}")
            return False, f"Timeout setelah {timeout} detik"
        except Exception as e:
            logger.error(f"Error menjalankan command '{command}': {e}")
            return False, str(e)

    def _create_pre_restore_backup(self):
        """Buat backup keadaan saat ini sebelum restore."""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            pre_restore_dir = os.path.join(self.backup_dir, f"pre_restore_{timestamp}")
            
            logger.info(f"Membuat backup pre-restore ke: {pre_restore_dir}")
            
            # Buat direktori backup
            os.makedirs(pre_restore_dir, exist_ok=True)
            
            # Backup direktori web saat ini
            cmd = f"cp -r {self.web_dir} {pre_restore_dir}/web_current"
            success, output = self._run_command(cmd)
            
            if success:
                logger.info(f"Backup pre-restore berhasil dibuat: {pre_restore_dir}")
                return pre_restore_dir
            else:
                logger.error(f"Gagal membuat backup pre-restore: {output}")
                return None
                
        except Exception as e:
            logger.error(f"Error saat membuat backup pre-restore: {e}")
            return None

    def _find_latest_backup(self, backup_source="local"):
        """Cari backup terbaru dari sumber yang ditentukan."""
        try:
            if backup_source == "local":
                backup_base_dir = self.local_backup_path
            else:
                # Untuk remote, kita perlu download dulu atau akses via SSH
                backup_base_dir = self._get_remote_backup_list()
                
            if not backup_base_dir or not os.path.exists(backup_base_dir):
                logger.error(f"Direktori backup tidak ditemukan: {backup_base_dir}")
                return None
                
            # Cari backup terbaru berdasarkan timestamp
            backup_dirs = []
            for item in os.listdir(backup_base_dir):
                item_path = os.path.join(backup_base_dir, item)
                if os.path.isdir(item_path) and item.startswith("backup_"):
                    backup_dirs.append((item, os.path.getctime(item_path)))
            
            if not backup_dirs:
                logger.error(f"Tidak ada backup ditemukan di: {backup_base_dir}")
                return None
                
            # Sort berdasarkan waktu pembuatan, terbaru dulu
            backup_dirs.sort(key=lambda x: x[1], reverse=True)
            latest_backup = backup_dirs[0][0]
            latest_backup_path = os.path.join(backup_base_dir, latest_backup)
            
            logger.info(f"Backup terbaru ditemukan: {latest_backup_path}")
            return latest_backup_path
            
        except Exception as e:
            logger.error(f"Error saat mencari backup terbaru: {e}")
            return None

    def _get_remote_backup_list(self):
        """Download atau akses daftar backup remote."""
        try:
            if not self.monitoring_server:
                logger.warning("Server monitoring tidak dikonfigurasi")
                return None
                
            # Buat direktori temporary untuk remote backup
            temp_remote_dir = os.path.join(self.backup_dir, "remote_temp")
            os.makedirs(temp_remote_dir, exist_ok=True)
            
            # Download backup list menggunakan scp atau rsync
            if self.monitoring_password:
                # Gunakan sshpass jika password tersedia
                cmd = f"sshpass -p '{self.monitoring_password}' rsync -av {self.monitoring_user}@{self.monitoring_server}:{self.remote_backup_path}/ {temp_remote_dir}/"
            else:
                # Gunakan SSH key
                cmd = f"rsync -av {self.monitoring_user}@{self.monitoring_server}:{self.remote_backup_path}/ {temp_remote_dir}/"
            
            success, output = self._run_command(cmd, timeout=600)  # 10 menit timeout untuk download
            
            if success:
                logger.info("Remote backup berhasil di-download")
                return temp_remote_dir
            else:
                logger.error(f"Gagal download remote backup: {output}")
                return None
                
        except Exception as e:
            logger.error(f"Error saat mengakses remote backup: {e}")
            return None

    def _perform_restore(self, backup_path):
        """Lakukan proses restore dari backup path."""
        try:
            logger.info(f"Memulai proses restore dari: {backup_path}")
            
            # Validasi backup path
            if not os.path.exists(backup_path):
                logger.error(f"Path backup tidak ditemukan: {backup_path}")
                return False
                
            # Cari file backup web
            web_backup_file = None
            for item in os.listdir(backup_path):
                if item.endswith('.tar.gz') and 'web' in item:
                    web_backup_file = os.path.join(backup_path, item)
                    break
            
            if not web_backup_file:
                logger.error(f"File backup web tidak ditemukan di: {backup_path}")
                return False
            
            # Buat backup pre-restore
            pre_restore_backup = self._create_pre_restore_backup()
            if not pre_restore_backup:
                logger.warning("Gagal membuat backup pre-restore, melanjutkan restore...")
            
            # Hentikan web server sementara
            logger.info("Menghentikan web server...")
            self._run_command("systemctl stop apache2")
            self._run_command("systemctl stop nginx")  # Jika ada nginx
            
            time.sleep(2)  # Tunggu sebentar
            
            # Backup direktori web saat ini
            current_web_backup = f"{self.web_dir}.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            cmd = f"mv {self.web_dir} {current_web_backup}"
            self._run_command(cmd)
            
            # Extract backup ke direktori web
            logger.info(f"Mengextract backup: {web_backup_file}")
            
            # Buat direktori web baru
            os.makedirs(self.web_dir, exist_ok=True)
            
            # Extract file backup
            cmd = f"tar -xzf {web_backup_file} -C {self.web_dir} --strip-components=1"
            success, output = self._run_command(cmd)
            
            if not success:
                logger.error(f"Gagal extract backup: {output}")
                # Rollback
                self._run_command(f"rm -rf {self.web_dir}")
                self._run_command(f"mv {current_web_backup} {self.web_dir}")
                return False
            
            # Set permission yang benar
            self._set_web_permissions()
            
            # Restart web server
            logger.info("Memulai ulang web server...")
            self._run_command("systemctl start apache2")
            
            # Verifikasi restore
            if self._verify_restore():
                logger.info("Restore berhasil diselesaikan")
                # Hapus backup current yang sudah diganti
                self._run_command(f"rm -rf {current_web_backup}")
                return True
            else:
                logger.error("Verifikasi restore gagal")
                return False
                
        except Exception as e:
            logger.error(f"Error saat melakukan restore: {e}")
            return False

    def _set_web_permissions(self):
        """Set permission yang benar untuk direktori web."""
        try:
            # Set ownership ke www-data
            cmd = f"chown -R www-data:www-data {self.web_dir}"
            self._run_command(cmd)
            
            # Set permission direktori dan file
            self._run_command(f"find {self.web_dir} -type d -exec chmod 755 {{}} \\;")
            self._run_command(f"find {self.web_dir} -type f -exec chmod 644 {{}} \\;")
            
            logger.info("Permission web directory berhasil di-set")
            
        except Exception as e:
            logger.error(f"Error saat set permission: {e}")

    def _verify_restore(self):
        """Verifikasi bahwa restore berhasil."""
        try:
            # Cek apakah direktori web ada dan tidak kosong
            if not os.path.exists(self.web_dir) or not os.listdir(self.web_dir):
                logger.error("Direktori web kosong setelah restore")
                return False
            
            # Cek apakah web server running
            result = subprocess.run(
                "systemctl is-active apache2", 
                shell=True, 
                capture_output=True, 
                text=True
            )
            
            if result.returncode != 0:
                logger.error("Apache2 tidak berjalan setelah restore")
                return False
            
            # Cek apakah website dapat diakses (optional)
            try:
                import requests
                response = requests.get("http://localhost", timeout=10)
                if response.status_code == 200:
                    logger.info("Website dapat diakses setelah restore")
                else:
                    logger.warning(f"Website return status code: {response.status_code}")
            except ImportError:
                logger.info("Requests library tidak tersedia, skip HTTP check")
            except Exception as e:
                logger.warning(f"HTTP check gagal: {e}")
            
            logger.info("Verifikasi restore berhasil")
            return True
            
        except Exception as e:
            logger.error(f"Error saat verifikasi restore: {e}")
            return False

    def process_wazuh_alert(self, alert_data_str):
        """Proses alert dari Wazuh untuk auto restore."""
        logger.info("Menerima data alert dari Wazuh untuk auto restore.")
        
        try:
            alert = json.loads(alert_data_str)
            self.current_alert_context = alert
            logger.debug(f"Data alert yang di-parse: {alert}")
        except json.JSONDecodeError as e:
            logger.error(f"Format data alert Wazuh tidak valid: {e}. Data: {alert_data_str[:200]}...")
            return False
        
        rule_id = str(alert.get('rule', {}).get('id', ''))
        file_path = alert.get('syscheck', {}).get('path')
        description = alert.get('rule', {}).get('description', 'N/A')
        
        logger.info(f"Memproses alert auto restore - Rule ID: {rule_id}, File: {file_path}, Deskripsi: {description}")
        
        # Ambil rule IDs dari konfigurasi untuk auto restore
        restore_rule_ids = self.config.get("RESTORE_RULE_IDS", "100010,100011,100012").split(',')
        restore_rule_ids = [rid.strip() for rid in restore_rule_ids]
        
        if rule_id in restore_rule_ids:
            logger.info(f"Rule ID {rule_id} memicu auto restore")
            
            # Tentukan sumber backup berdasarkan rule ID atau konfigurasi
            backup_source = "local"  # Default ke local backup
            
            # Bisa dikustomisasi berdasarkan rule ID
            if rule_id in ["100011", "100012"]:  # Rule untuk restore dari remote
                backup_source = "remote"
            
            # Cari backup terbaru
            backup_path = self._find_latest_backup(backup_source)
            if not backup_path:
                logger.error(f"Tidak dapat menemukan backup untuk restore dari sumber: {backup_source}")
                return False
            
            # Lakukan auto restore
            success = self._perform_restore(backup_path)
            
            if success:
                logger.info(f"Auto restore berhasil dari {backup_source} backup: {backup_path}")
                
                # Log ke file terpisah untuk audit
                audit_log = f"/var/log/soc-restore-audit.log"
                try:
                    with open(audit_log, 'a') as f:
                        f.write(f"{datetime.now().isoformat()} - Auto restore berhasil - Rule: {rule_id}, Source: {backup_source}, Path: {backup_path}\n")
                except Exception as e:
                    logger.warning(f"Gagal menulis audit log: {e}")
                
                return True
            else:
                logger.error(f"Auto restore gagal dari {backup_source} backup: {backup_path}")
                return False
        else:
            logger.info(f"Rule ID {rule_id} tidak memicu auto restore")
            return False

    def manual_restore(self, backup_source="local", backup_path=None):
        """Lakukan restore manual."""
        try:
            logger.info(f"Memulai manual restore dari sumber: {backup_source}")
            
            if backup_path:
                # Gunakan backup path yang ditentukan
                if not os.path.exists(backup_path):
                    logger.error(f"Backup path tidak ditemukan: {backup_path}")
                    return False
                restore_path = backup_path
            else:
                # Cari backup terbaru
                restore_path = self._find_latest_backup(backup_source)
                if not restore_path:
                    logger.error(f"Tidak dapat menemukan backup untuk restore")
                    return False
            
            # Konfirmasi restore (dalam mode manual)
            logger.info(f"Akan melakukan restore dari: {restore_path}")
            
            # Lakukan restore
            success = self._perform_restore(restore_path)
            
            if success:
                logger.info("Manual restore berhasil")
                print(f"Restore berhasil dari: {restore_path}")
                return True
            else:
                logger.error("Manual restore gagal")
                print(f"Restore gagal dari: {restore_path}")
                return False
                
        except Exception as e:
            logger.error(f"Error saat manual restore: {e}")
            print(f"Error: {e}")
            return False


def main():
    """Main function untuk Active Response dari Wazuh atau manual operation."""
    try:
        # Inisialisasi restore manager
        restore_manager = AutoRestoreManager()
        
        # Cek apakah ada argumen untuk operasi manual
        if len(sys.argv) > 1:
            command = sys.argv[1].lower()
            
            if command == "manual-restore":
                backup_source = sys.argv[2] if len(sys.argv) > 2 else "local"
                backup_path = sys.argv[3] if len(sys.argv) > 3 else None
                
                if backup_source not in ["local", "remote"]:
                    print("Error: backup_source harus 'local' atau 'remote'")
                    sys.exit(1)
                
                success = restore_manager.manual_restore(backup_source, backup_path)
                sys.exit(0 if success else 1)
                
            elif command == "list-backups":
                backup_source = sys.argv[2] if len(sys.argv) > 2 else "local"
                
                if backup_source == "local":
                    backup_dir = restore_manager.local_backup_path
                    if os.path.exists(backup_dir):
                        backups = [d for d in os.listdir(backup_dir) if d.startswith("backup_")]
                        backups.sort(reverse=True)
                        print(f"Backup lokal yang tersedia ({len(backups)}):")
                        for backup in backups[:10]:  # Show last 10
                            backup_path = os.path.join(backup_dir, backup)
                            mtime = datetime.fromtimestamp(os.path.getctime(backup_path))
                            print(f"  {backup} - {mtime.strftime('%Y-%m-%d %H:%M:%S')}")
                    else:
                        print("Direktori backup lokal tidak ditemukan")
                else:
                    print("List remote backup belum diimplementasi")
                
                sys.exit(0)
                
            elif command == "verify-config":
                try:
                    restore_manager._validate_config()
                    print("Konfigurasi valid")
                    sys.exit(0)
                except ValueError as e:
                    print(f"Konfigurasi tidak valid: {e}")
                    sys.exit(1)
                    
            else:
                logger.error(f"Command tidak dikenali: {command}")
                print("Usage: restore_auto.py [manual-restore [local|remote] [backup_path]|list-backups [local|remote]|verify-config]")
                sys.exit(1)
        
        # Mode Wazuh Active Response - baca alert dari stdin
        logger.info("Menunggu data alert dari Wazuh Active Response...")
        
        try:
            alert_data = sys.stdin.read().strip()
            if not alert_data:
                logger.error("Tidak ada data alert yang diterima dari stdin.")
                sys.exit(1)
                
            logger.info(f"Data alert diterima: {alert_data[:100]}...")
            
            # Proses alert
            success = restore_manager.process_wazuh_alert(alert_data)
            sys.exit(0 if success else 1)
            
        except Exception as e:
            logger.error(f"Error membaca alert data dari stdin: {e}")
            sys.exit(1)
            
    except Exception as e:
        logger.error(f"Error dalam main function: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
