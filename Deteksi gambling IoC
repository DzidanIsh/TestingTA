#!/usr/bin/env python3
import json
import datetime
import os

# --- Konfigurasi ---
# File alerts.json utama Wazuh
ALERTS_FILE = '/var/ossec/logs/alerts/alerts.json'
# File tujuan untuk menyimpan laporan dari alert terakhir
OUTPUT_FILE = '/tmp/active_response_500550.log'
# File log untuk proses debugging skrip ini sendiri
LOG_FILE = '/tmp/find_last_500550_debug.log'
# Rule ID yang dicari
TARGET_RULE_ID = "500550"

def log_debug(msg):
    """Fungsi untuk menulis log debug."""
    with open(LOG_FILE, 'a') as f:
        f.write(f"{datetime.datetime.now()} - {msg}\n")

def main():
    log_debug(f"Skrip find_last_{TARGET_RULE_ID}.py dimulai.")

    # Cek apakah file alerts.json ada
    if not os.path.isfile(ALERTS_FILE):
        log_debug(f"Error: File {ALERTS_FILE} tidak ditemukan!")
        return

    # Membaca semua baris dari file alerts.json
    try:
        with open(ALERTS_FILE, 'r') as f:
            lines = f.readlines()
        log_debug(f"Berhasil membaca {len(lines)} baris dari {ALERTS_FILE}.")
    except Exception as e:
        log_debug(f"Error: Gagal membaca file alerts: {str(e)}")
        return

    latest_alert = None
    # Mencari dari baris terakhir ke atas untuk efisiensi
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        try:
            alert = json.loads(line)
            # Memeriksa apakah rule.id di dalam JSON cocok dengan target
            if str(alert.get('rule', {}).get('id')) == TARGET_RULE_ID:
                latest_alert = alert
                log_debug(f"Menemukan alert yang cocok dengan ID {TARGET_RULE_ID}. Alert ID: {alert.get('id')}")
                break  # Berhenti setelah menemukan yang pertama dari belakang
        except Exception:
            # Mengabaikan baris yang bukan format JSON yang valid
            continue

    # Jika alert yang cocok ditemukan, tulis ke file output
    if latest_alert:
        try:
            with open(OUTPUT_FILE, 'w') as out:
                out.write("==== INCIDENT REPORT (Last Alert Found) ====\n")
                # Menggunakan json.dumps untuk format yang lebih rapi
                out.write(json.dumps(latest_alert, indent=4))
                out.write("\n==== END OF REPORT ====\n")
            log_debug(f"Berhasil menulis laporan ke {OUTPUT_FILE}")
        except Exception as e:
            log_debug(f"Error: Gagal menulis file output: {str(e)}")
    else:
        # Pesan log jika tidak ada alert yang cocok ditemukan
        log_debug(f"Tidak menemukan alert dengan rule_id {TARGET_RULE_ID} di seluruh file.")

if __name__ == "__main__":
    main()
