#!/usr/bin/env python3

"""
SOC Eradication Script - NIST 800-61 Incident Response Framework
Eradication Phase: Menghilangkan ancaman dari sistem dan mencegah penyebaran
"""

import os
import sys
import json
import logging
import shutil
import hashlib
import re
from datetime import datetime
from pathlib import Path

try:
    import magic
except ImportError:
    magic = None
    logging.warning("Library 'python-magic' tidak terinstal. Deteksi tipe MIME mungkin kurang akurat.")

try:
    import yara
except ImportError:
    yara = None
    logging.warning("Library 'yara-python' tidak terinstal. Scan YARA akan dinonaktifkan.")

try:
    import pyclamd
except ImportError:
    pyclamd = None
    logging.warning("Library 'pyclamd' tidak terinstal. Scan ClamAV akan dinonaktifkan.")

try:
    import requests
except ImportError:
    requests = None
    logging.warning("Library 'requests' tidak terinstal. Integrasi YETI akan dinonaktifkan.")


# Konfigurasi logging
LOG_FILE = "/var/log/wazuh/active-response/eradication.log"

try:
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
except OSError as e:
    print(f"Warning: Tidak dapat membuat direktori log {os.path.dirname(LOG_FILE)}. Error: {e}", file=sys.stderr)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('soc_eradication')

# Support untuk multiple config path
CONFIG_FILES = ["/etc/soc-config/config.conf", "/etc/web-backup/config.conf"]

class EradicationManager:
    def __init__(self):
        self.config = self._load_config()

        self.quarantine_dir = self.config.get("QUARANTINE_DIR", "/var/soc-quarantine")
        self.yara_rules_dir = self.config.get("YARA_RULES_DIR", "/var/ossec/etc/rules/yara")
        self.clamd_socket_path = self.config.get("CLAMD_SOCKET", "/var/run/clamav/clamd.ctl")

        # Pola suspicious untuk deteksi
        suspicious_patterns_str = self.config.get("ERADICATION_SUSPICIOUS_PATTERNS")
        if suspicious_patterns_str:
            self.suspicious_patterns = [p.strip() for p in suspicious_patterns_str.split('|||')]
        else:
            self.suspicious_patterns = [
                r'(?i)(eval\s*\(base64_decode\s*\()',
                r'(?i)(passthru\s*\()',
                r'(?i)(shell_exec\s*\()',
                r'(?i)(system\s*\()',
                r'(?i)(exec\s*\()',
                r'(?i)(preg_replace\s*\(.*\/e\s*\))',
                r'(?i)(FilesMan|phpfm|P\.A\.S\.|\bWebShell\b|r57shell|c99shell)',
                r'(?i)(document\.write\s*\(\s*unescape\s*\()',
                r'(?i)(<iframe\s*src\s*=\s*["\']javascript:)',
                r'(?i)(fsockopen|pfsockopen)\s*\(',
            ]

        self.clamav_enabled = self._check_clamav_availability()
        self.yara_enabled = self._check_yara_availability()
        self.magic_enabled = magic is not None
        self.setup_quarantine_dir()
        self.staging_dir = "/tmp/soc_scan_staging"
        os.makedirs(self.staging_dir, exist_ok=True)

        # Konfigurasi YETI
        self.yeti_enabled = self.config.get("YETI_ENABLED", "false").lower() == "true"
        self.yeti_api_url = self.config.get("YETI_API_URL", "")
        self.yeti_api_key = self.config.get("YETI_API_KEY", "")
        self.yeti_session = None

        if self.yeti_enabled:
            if not requests:
                logger.error("Integrasi YETI diaktifkan tapi library 'requests' tidak ditemukan. Menonaktifkan integrasi.")
                self.yeti_enabled = False
            elif not self.yeti_api_url or not self.yeti_api_key:
                logger.error("Integrasi YETI diaktifkan tapi YETI_API_URL atau YETI_API_KEY tidak dikonfigurasi. Menonaktifkan integrasi.")
                self.yeti_enabled = False
            else:
                self.yeti_session = requests.Session()
                self.yeti_session.headers.update({'X-Api-Key': self.yeti_api_key, 'Accept': 'application/json'})
                logger.info("Integrasi YETI diaktifkan.")

        # Untuk menyimpan konteks alert saat ini
        self.current_alert_context = {}

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

    def _check_clamav_availability(self):
        """Periksa ketersediaan ClamAV."""
        if pyclamd is None:
            logger.error("Library pyclamd tidak tersedia. ClamAV dinonaktifkan.")
            return False
        try:
            # Coba beberapa lokasi socket yang umum
            possible_socket_paths = [
                self.clamd_socket_path,
                "/var/run/clamav/clamd.ctl",
                "/var/run/clamd.ctl",
                "/var/run/clamav/clamd.sock"
            ]

            connected = False
            for socket_path in possible_socket_paths:
                try:
                    logger.debug(f"Mencoba menghubungkan ke ClamAV daemon di {socket_path}")
                    cd = pyclamd.ClamdUnixSocket(socket_path)
                    ping_result = cd.ping()
                    if ping_result:
                        self.clamd_client = cd
                        self.clamd_socket_path = socket_path
                        logger.info(f"Koneksi ke ClamAV berhasil via pyclamd di {socket_path}")
                        connected = True
                        break
                except Exception as e:
                    logger.debug(f"Gagal mencoba socket {socket_path}: {e}")
                    continue

            if not connected:
                logger.error("Tidak dapat terhubung ke ClamAV daemon di semua lokasi yang mungkin")
                return False

            return True
        except Exception as e:
            logger.error(f"Gagal menghubungi ClamAV daemon: {e}", exc_info=True)
            return False

    def _check_yara_availability(self):
        """Periksa ketersediaan YARA."""
        if yara is None: 
            return False
        if not os.path.isdir(self.yara_rules_dir):
            logger.warning(f"Direktori YARA rules '{self.yara_rules_dir}' tidak ditemukan. Scan YARA dinonaktifkan.")
            return False
        try:
            rule_files = [os.path.join(self.yara_rules_dir, f) for f in os.listdir(self.yara_rules_dir) if f.endswith(('.yar', '.yara'))]
            if not rule_files:
                logger.warning(f"Tidak ada file rule YARA (.yar/.yara) ditemukan di '{self.yara_rules_dir}'. Scan YARA dinonaktifkan.")
                return False
            logger.info(f"Direktori YARA rules '{self.yara_rules_dir}' dan rules ditemukan. Scan YARA diaktifkan.")
            return True
        except Exception as e:
            logger.error(f"Error saat memeriksa YARA rules: {e}. Scan YARA dinonaktifkan.")
            return False

    def setup_quarantine_dir(self):
        """Setup direktori karantina."""
        try:
            if not os.path.exists(self.quarantine_dir):
                os.makedirs(self.quarantine_dir, mode=0o750)
                logger.info(f"Direktori karantina dibuat di {self.quarantine_dir}")
            os.chmod(self.quarantine_dir, 0o750)
            return True
        except Exception as e:
            logger.error(f"Gagal membuat atau mengatur izin direktori karantina '{self.quarantine_dir}': {e}")
            return False

    def calculate_file_hash(self, file_path, hash_alg="sha256"):
        """Hitung hash file."""
        h = hashlib.new(hash_alg)
        try:
            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(4096)
                    if not chunk: 
                        break
                    h.update(chunk)
            return h.hexdigest()
        except Exception as e:
            logger.error(f"Gagal menghitung hash untuk file {file_path}: {e}")
            return None

    def _send_observable_to_yeti(self, value, obs_type, description="", tags=None, source="SOC_EradicationScript"):
        """Kirim observable ke YETI untuk threat intelligence."""
        if not self.yeti_enabled or not self.yeti_session:
            return False
            
        try:
            data = {
                "value": value,
                "type": obs_type,
                "description": description,
                "tags": tags or [],
                "source": source
            }
            
            response = self.yeti_session.post(f"{self.yeti_api_url}observables/", json=data, timeout=10)
            if response.status_code in [200, 201]:
                logger.info(f"Observable berhasil dikirim ke YETI: {value} ({obs_type})")
                return True
            else:
                logger.warning(f"Gagal mengirim observable ke YETI. Status: {response.status_code}, Response: {response.text}")
                return False
        except Exception as e:
            logger.error(f"Error saat mengirim observable ke YETI: {e}")
            return False

    def _enrich_yeti_with_finding(self, file_path, detection_method, details=""):
        """Kirim informasi temuan ke YETI untuk enrichment."""
        if not self.yeti_enabled:
            return
            
        try:
            file_hash = self.calculate_file_hash(file_path)
            if file_hash:
                tags = ["malware", "detected", detection_method.lower()]
                description = f"Malicious file detected by {detection_method}. File: {file_path}. Details: {details}"
                self._send_observable_to_yeti(file_hash, "hash", description, tags)
                
            # Juga kirim path file sebagai observabel
            self._send_observable_to_yeti(file_path, "file", f"Malicious file path detected by {detection_method}", 
                                        ["malware", "file_path"])
        except Exception as e:
            logger.error(f"Error saat mengirim enrichment ke YETI: {e}")

    def scan_with_clamav(self, file_path):
        """Scan file menggunakan ClamAV."""
        if not self.clamav_enabled:
            return False, "ClamAV tidak tersedia"
            
        try:
            result = self.clamd_client.scan_file(file_path)
            if result is None:
                return False, "File bersih menurut ClamAV"
            else:
                # ClamAV mengembalikan tuple (filename, status) jika terinfeksi
                if isinstance(result, dict) and file_path in result:
                    status = result[file_path]
                    if status[0] == 'FOUND':
                        malware_name = status[1]
                        logger.warning(f"ClamAV mendeteksi malware: {file_path} -> {malware_name}")
                        self._enrich_yeti_with_finding(file_path, "ClamAV", f"Malware: {malware_name}")
                        return True, f"Malware terdeteksi: {malware_name}"
                return False, "File bersih menurut ClamAV"
        except Exception as e:
            logger.error(f"Error saat scan ClamAV untuk file {file_path}: {e}")
            return False, f"Error ClamAV: {str(e)}"

    def scan_with_yara(self, file_path):
        """Scan file menggunakan YARA rules."""
        if not self.yara_enabled:
            return False, "YARA tidak tersedia"
            
        try:
            rule_files = [os.path.join(self.yara_rules_dir, f) for f in os.listdir(self.yara_rules_dir) 
                         if f.endswith(('.yar', '.yara'))]
            
            for rule_file in rule_files:
                try:
                    rules = yara.compile(rule_file)
                    matches = rules.match(file_path)
                    if matches:
                        matched_rules = [str(match) for match in matches]
                        logger.warning(f"YARA mendeteksi pattern mencurigakan: {file_path} -> {matched_rules}")
                        self._enrich_yeti_with_finding(file_path, "YARA", f"Rules matched: {matched_rules}")
                        return True, f"YARA rules matched: {', '.join(matched_rules)}"
                except Exception as e:
                    logger.warning(f"Error saat memproses YARA rule {rule_file}: {e}")
                    continue
            
            return False, "Tidak ada YARA rule yang cocok"
        except Exception as e:
            logger.error(f"Error saat scan YARA untuk file {file_path}: {e}")
            return False, f"Error YARA: {str(e)}"

    def check_suspicious_content(self, file_path):
        """Periksa konten file untuk pattern mencurigakan."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            for pattern in self.suspicious_patterns:
                if re.search(pattern, content):
                    logger.warning(f"Pattern mencurigakan ditemukan di {file_path}: {pattern}")
                    self._enrich_yeti_with_finding(file_path, "Pattern_Match", f"Suspicious pattern: {pattern}")
                    return True, f"Pattern mencurigakan: {pattern}"
                    
            return False, "Tidak ada pattern mencurigakan ditemukan"
        except Exception as e:
            logger.error(f"Error saat memeriksa konten file {file_path}: {e}")
            return False, f"Error reading file: {str(e)}"

    def quarantine_file(self, file_path, detection_reason="Unknown"):
        """Karantina file yang terdeteksi berbahaya."""
        try:
            if not os.path.exists(file_path):
                logger.warning(f"File untuk karantina tidak ditemukan: {file_path}")
                return False
                
            file_hash = self.calculate_file_hash(file_path)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Buat nama file karantina yang unik
            original_name = os.path.basename(file_path)
            quarantine_name = f"{timestamp}_{file_hash[:8]}_{original_name}"
            quarantine_path = os.path.join(self.quarantine_dir, quarantine_name)
            
            # Pindahkan file ke karantina
            shutil.move(file_path, quarantine_path)
            
            # Buat metadata file
            metadata_path = quarantine_path + ".metadata"
            metadata = {
                "original_path": file_path,
                "quarantine_time": timestamp,
                "file_hash": file_hash,
                "detection_reason": detection_reason,
                "file_size": os.path.getsize(quarantine_path),
                "alert_context": self.current_alert_context
            }
            
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            logger.info(f"File berhasil dikarantina: {file_path} -> {quarantine_path}")
            logger.info(f"Alasan karantina: {detection_reason}")
            
            # Kirim hash ke YETI sebagai IOC
            if file_hash:
                self._send_observable_to_yeti(file_hash, "hash", 
                                            f"Quarantined file hash. Reason: {detection_reason}", 
                                            ["quarantine", "malware"])
            
            return True
        except Exception as e:
            logger.error(f"Gagal mengkarantina file {file_path}: {e}", exc_info=True)
            return False

    def _perform_all_scans_on_file(self, file_path):
        """Lakukan semua jenis scan pada file."""
        results = []
        
        # ClamAV scan
        clamav_detected, clamav_detail = self.scan_with_clamav(file_path)
        if clamav_detected:
            results.append(("ClamAV", clamav_detail))
        
        # YARA scan
        yara_detected, yara_detail = self.scan_with_yara(file_path)
        if yara_detected:
            results.append(("YARA", yara_detail))
        
        # Pattern scan
        pattern_detected, pattern_detail = self.check_suspicious_content(file_path)
        if pattern_detected:
            results.append(("Pattern", pattern_detail))
        
        return results

    def scan_directory(self, directory_to_scan):
        """Scan direktori untuk file berbahaya."""
        logger.info(f"Memulai scan direktori: {directory_to_scan}")
        quarantined_files = []
        
        try:
            for root, dirs, files in os.walk(directory_to_scan):
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    # Skip file yang sangat besar (>100MB) untuk efisiensi
                    try:
                        if os.path.getsize(file_path) > 100 * 1024 * 1024:
                            logger.info(f"Melewati file besar: {file_path}")
                            continue
                    except OSError:
                        continue
                    
                    # Lakukan scan
                    detections = self._perform_all_scans_on_file(file_path)
                    
                    if detections:
                        detection_summary = "; ".join([f"{method}: {detail}" for method, detail in detections])
                        logger.warning(f"File berbahaya terdeteksi: {file_path} - {detection_summary}")
                        
                        if self.quarantine_file(file_path, detection_summary):
                            quarantined_files.append((file_path, detection_summary))
        
        except Exception as e:
            logger.error(f"Error saat scan direktori {directory_to_scan}: {e}")
        
        logger.info(f"Scan direktori selesai. {len(quarantined_files)} file dikarantina.")
        return quarantined_files

    def process_wazuh_alert(self, alert_data_str):
        """Proses alert dari Wazuh untuk eradication."""
        logger.info("Menerima data alert dari Wazuh untuk eradication.")
        
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
        
        logger.info(f"Memproses alert eradication - Rule ID: {rule_id}, File: {file_path}, Deskripsi: {description}")
        
        actions_performed = []
        
        # Ambil rule IDs dari konfigurasi untuk eradication
        eradication_rule_ids = self.config.get("ATTACK_RULE_IDS", "5710,5712,5715,5760,100003,100004").split(',')
        eradication_rule_ids = [rid.strip() for rid in eradication_rule_ids]
        
        if rule_id in eradication_rule_ids:
            if file_path and os.path.exists(file_path):
                logger.info(f"Melakukan eradication untuk file: {file_path}")
                
                # Scan file yang terkait dengan alert
                detections = self._perform_all_scans_on_file(file_path)
                
                if detections:
                    detection_summary = "; ".join([f"{method}: {detail}" for method, detail in detections])
                    if self.quarantine_file(file_path, f"Alert Rule {rule_id}: {detection_summary}"):
                        actions_performed.append(f"File quarantined: {file_path}")
                        logger.info(f"File berhasil dikarantina: {file_path}")
                else:
                    logger.info(f"Tidak ada ancaman terdeteksi pada file: {file_path}")
            
            # Scan direktori web untuk ancaman lain
            web_dir = self.config.get("WEB_DIR")
            if web_dir and os.path.isdir(web_dir):
                logger.info(f"Melakukan scan eradication pada direktori web: {web_dir}")
                quarantined_files = self.scan_directory(web_dir)
                if quarantined_files:
                    actions_performed.append(f"Directory scan: {len(quarantined_files)} files quarantined")
        
        # Log hasil eradication
        if actions_performed:
            summary = f"Eradication actions completed: {', '.join(actions_performed)}"
            logger.info(summary)
            return True
        else:
            logger.info(f"Tidak ada tindakan eradication yang diperlukan untuk rule ID: {rule_id}")
            return False


def main():
    """Main function untuk Active Response dari Wazuh."""
    try:
        # Inisialisasi eradication manager
        eradication = EradicationManager()
        
        # Cek apakah ada argumen untuk operasi manual
        if len(sys.argv) > 1:
            command = sys.argv[1].lower()
            
            if command == "scan-file" and len(sys.argv) > 2:
                file_path = sys.argv[2]
                if os.path.exists(file_path):
                    detections = eradication._perform_all_scans_on_file(file_path)
                    if detections:
                        print(f"Ancaman terdeteksi pada {file_path}:")
                        for method, detail in detections:
                            print(f"  {method}: {detail}")
                        sys.exit(1)
                    else:
                        print(f"Tidak ada ancaman terdeteksi pada {file_path}")
                        sys.exit(0)
                else:
                    print(f"File tidak ditemukan: {file_path}")
                    sys.exit(1)
                    
            elif command == "scan-directory" and len(sys.argv) > 2:
                directory = sys.argv[2]
                if os.path.isdir(directory):
                    quarantined = eradication.scan_directory(directory)
                    print(f"Scan selesai. {len(quarantined)} file dikarantina.")
                    if quarantined:
                        for file_path, reason in quarantined:
                            print(f"  Quarantined: {file_path} - {reason}")
                    sys.exit(0)
                else:
                    print(f"Direktori tidak ditemukan: {directory}")
                    sys.exit(1)
                    
            elif command == "quarantine-file" and len(sys.argv) > 2:
                file_path = sys.argv[2]
                reason = sys.argv[3] if len(sys.argv) > 3 else "Manual quarantine"
                success = eradication.quarantine_file(file_path, reason)
                sys.exit(0 if success else 1)
                
            else:
                logger.error(f"Command tidak dikenali: {command}")
                print("Usage: eradication.py [scan-file <path>|scan-directory <path>|quarantine-file <path> [reason]]")
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
            success = eradication.process_wazuh_alert(alert_data)
            sys.exit(0 if success else 1)
            
        except Exception as e:
            logger.error(f"Error membaca alert data dari stdin: {e}")
            sys.exit(1)
            
    except Exception as e:
        logger.error(f"Error dalam main function: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
