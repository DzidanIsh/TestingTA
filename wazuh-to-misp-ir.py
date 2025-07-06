#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# wazuh-to-misp-ir.py
#
# Deskripsi: Skrip Active Response untuk Wazuh yang mengambil alert,
# mengekstrak IoC, dan membuat event baru di MISP.
#
# Tujuan: Mengotomatiskan fase 'Post-Incident Activity' dari NIST 800-61r2
# dengan mengubah deteksi menjadi intelijen yang dapat ditindaklanjuti.
#
# Penulis: Cybersecurity Integration Specialist
# Versi: 1.0

import sys
import json
import logging
import os
from pymisp import PyMISP, MISPEvent

# --- KONFIGURASI ---
# Harap modifikasi variabel-variabel di bawah ini sesuai dengan lingkungan Anda.

# Konfigurasi MISP
MISP_URL = "https://your_misp_instance_url"  # Ganti dengan URL instance MISP Anda
MISP_KEY = "your_misp_api_key"  # Ganti dengan kunci API MISP Anda [19]
MISP_VERIFYCERT = True  # Set ke False jika Anda menggunakan sertifikat self-signed (tidak direkomendasikan untuk produksi)

# Konfigurasi Logging
LOG_FILE = "/var/ossec/logs/active-responses.log"
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(levelname)s: %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')

# Tambahkan handler untuk menulis log ke file yang ditentukan
# Ini adalah praktik terbaik untuk debugging integrasi [33]
file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: wazuh-to-misp: %(message)s'))
logger = logging.getLogger()
# Hapus handler default jika ada, untuk menghindari duplikasi log ke console/ossec.log
if logger.hasHandlers():
    logger.handlers.clear()
logger.addHandler(file_handler)

# --- LOGIKA PEMETAAN ---

# Kamus Pemetaan IoC: Memetakan rule.id Wazuh ke field yang relevan dan tipe atribut MISP
# Format: 'rule_id': [('path.ke.field.di.alert.json', 'tipe-atribut-misp'),...]
IOC_MAPPING = {
    # Aturan Keamanan SSH
    '5710': [('data.srcip', 'ip-src')],  # Upaya login dengan user tidak ada [24]
    '5712': [('data.srcip', 'ip-src')],  # Upaya brute force SSH
    '5716': [('data.srcip', 'ip-src')],  # Login SSH berhasil setelah beberapa kali gagal

    # Aturan File Integrity Monitoring (FIM)
    '550': [('syscheck.path', 'filename'), ('syscheck.sha256_after', 'sha256')], # File diubah
    '554': [('syscheck.path', 'filename')], # File ditambahkan

    # Aturan Windows Sysmon (Contoh ID aturan kustom)
    '100101': [('data.win.eventdata.destinationIp', 'ip-dst'), ('data.win.eventdata.image', 'filename')], # Sysmon - Network Connection
    '100102': [('data.win.eventdata.hashes', 'sha256'), ('data.win.eventdata.targetFilename', 'filename')], # Sysmon - CreateRemoteThread
    '100103': [('data.win.eventdata.queryName', 'domain')], # Sysmon - DNS Query

    # Aturan Web Log
    '31101': [('data.srcip', 'ip-src'), ('data.url', 'url')], # Permintaan web dengan kode respons 404
    '31108': [('data.srcip', 'ip-src'), ('data.url', 'url')], # Serangan SQL Injection
}

# --- FUNGSI-FUNGSI UTAMA ---

def parse_alert():
    """Membaca dan mem-parsing alert JSON dari STDIN."""
    try:
        raw_alert = sys.stdin.read()
        if not raw_alert:
            return None
        alert_json = json.loads(raw_alert)
        return alert_json
    except json.JSONDecodeError as e:
        logging.error(f"Gagal mem-parsing input JSON dari Wazuh. Error: {e}. Input mentah: {raw_alert[:500]}")
        return None
    except Exception as e:
        logging.error(f"Terjadi kesalahan tak terduga saat membaca alert dari STDIN: {e}")
        return None

def get_value_from_path(data, path):
    """Mengambil nilai dari nested dictionary menggunakan dot notation path."""
    keys = path.split('.')
    current_data = data
    for key in keys:
        if isinstance(current_data, dict) and key in current_data:
            current_data = current_data[key]
        else:
            return None
    
    # Menangani kasus khusus untuk field hash Sysmon yang mungkin mengandung beberapa hash
    if 'hashes' in path and isinstance(current_data, str) and 'SHA256=' in current_data:
        try:
            return current_data.split('SHA256=').split(',')
        except IndexError:
            return None # Format tidak terduga
            
    return current_data

def extract_iocs(alert):
    """Mengekstrak IoC dari alert berdasarkan IOC_MAPPING."""
    rule_id = alert.get('rule', {}).get('id')
    if not rule_id or rule_id not in IOC_MAPPING:
        return

    iocs =
    mappings = IOC_MAPPING[rule_id]
    for field_path, misp_type in mappings:
        value = get_value_from_path(alert, field_path)
        if value:
            iocs.append({'type': misp_type, 'value': value})
            logging.info(f"IoC diekstrak: Rule ID {rule_id}, Tipe: {misp_type}, Nilai: {value}")

    return iocs

def create_misp_event(alert, iocs):
    """Membuat dan mengirim event baru ke MISP."""
    if not iocs:
        logging.info("Tidak ada IoC yang diekstrak, tidak ada event MISP yang dibuat.")
        return

    try:
        misp = PyMISP(MISP_URL, MISP_KEY, MISP_VERIFYCERT)
        logging.info(f"Berhasil terhubung ke MISP di {MISP_URL}")
    except Exception as e:
        logging.error(f"Gagal menginisialisasi koneksi PyMISP: {e}")
        return

    # Membuat objek MISPEvent
    event = MISPEvent()
    rule_desc = alert.get('rule', {}).get('description', 'N/A')
    agent_name = alert.get('agent', {}).get('name', 'N/A')
    rule_level = alert.get('rule', {}).get('level', 0)
    rule_id = alert.get('rule', {}).get('id', 'N/A')

    # Mengisi metadata event untuk konteks maksimal
    event.info = f"Wazuh Alert: {rule_desc} on {agent_name}"
    event.distribution = 0  # 0: Your organisation only
    event.threat_level_id = 2 if rule_level >= 12 else 3 # 2: Medium, 3: Low
    event.analysis = 0  # 0: Initial

    # Menambahkan tag yang relevan
    event.add_tag("source:wazuh")
    event.add_tag(f"wazuh:rule-id:{rule_id}")
    event.add_tag(f"wazuh:level:{rule_level}")
    event.add_tag(f"wazuh:agent-name:{agent_name}")

    # Menambahkan atribut hostname dan IP agent yang terpengaruh untuk konteks
    event.add_attribute('hostname', agent_name, category='Network activity', comment='Affected Wazuh agent hostname')
    if alert.get('agent', {}).get('ip'):
        event.add_attribute('ip-dst', alert['agent']['ip'], category='Internal reference', comment='Affected Wazuh agent IP')

    # Menambahkan IoC yang diekstrak sebagai atribut
    for ioc in iocs:
        event.add_attribute(ioc['type'], ioc['value'])

    try:
        # Mengirim event ke MISP
        result = misp.add_event(event)
        if 'Event' in result and 'id' in result['Event']:
            logging.info(f"Berhasil membuat event MISP dengan ID: {result['Event']['id']}")
        else:
            # Menangani pesan error dari MISP yang mungkin tidak memiliki struktur 'Event'
            error_message = result.get('message', str(result))
            logging.error(f"Gagal membuat event MISP. Respons dari server: {error_message}")
    except Exception as e:
        logging.error(f"Terjadi kesalahan saat mengirim event ke MISP: {e}")

def main():
    """Fungsi utama untuk menjalankan alur kerja skrip."""
    logging.info("Skrip wazuh-to-misp-ir dimulai.")
    
    alert_data = parse_alert()
    if not alert_data:
        logging.warning("Input dari STDIN kosong atau tidak valid. Skrip dihentikan.")
        sys.exit(0)
        
    # Memeriksa apakah ini adalah alert yang valid untuk diproses
    # Sesuai dokumentasi, alert AR dibungkus dalam 'parameters' [15]
    if alert_data.get('command') == 'add' and 'rule' in alert_data.get('parameters', {}).get('alert', {}):
        alert_content = alert_data['parameters']['alert']
        iocs = extract_iocs(alert_content)
        create_misp_event(alert_content, iocs)
    else:
        # Ini mungkin pesan kontrol dari AR stateful, atau format yang tidak diharapkan. Kita abaikan.
        logging.info("Menerima pesan non-alert (misalnya, cek stateful atau format tidak dikenal), diabaikan.")

    logging.info("Skrip wazuh-to-misp-ir selesai.")

if __name__ == "__main__":
    main()
