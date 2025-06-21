#!/usr/bin/env python3

"""
SOC Restore Script - NIST 800-61 Incident Response Framework
Recovery Phase: Restore interaktif sistem dari backup (mode manual/interactive)
"""

import os
import sys
import argparse
import json
import base64
import subprocess
import logging
import getpass
import datetime
import git
from pathlib import Path
import shutil
import glob
import tarfile

# Konfigurasi logging
LOG_FILE = '/var/log/wazuh/active-response/restore.log'
try:
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
except OSError as e:
    sys.stderr.write(f"Warning: Tidak dapat membuat direktori log {os.path.dirname(LOG_FILE)}. Error: {e}\n")

# Handler logging
handlers_list = [logging.FileHandler(LOG_FILE)]
# Tambahkan StreamHandler hanya jika tidak ada argumen --auto atau --alert untuk menghindari output ganda
if not any(arg in sys.argv for arg in ['--auto', '--alert']):
    handlers_list.append(logging.StreamHandler(sys.stdout))

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=handlers_list
)
logger = logging.getLogger('soc_restore_interactive')

# Warna untuk output terminal
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    YELLOW = '\033[33m'

# Support untuk multiple config path
CONFIG_FILES = ["/etc/soc-config/config.conf", "/etc/web-backup/config.conf"]

def print_banner():
    """Menampilkan banner aplikasi"""
    banner = """
=================================================================
         SOC RESTORE INTERAKTIF - NIST 800-61 RECOVERY PHASE
=================================================================
    """
    print(Colors.HEADER + banner + Colors.ENDC)

def error_exit(message):
    """Menampilkan pesan error dan keluar"""
    logger.error(message)
    # Hanya print ke console jika bukan mode auto/alert yang mungkin outputnya ditangkap
    if not any(arg in sys.argv for arg in ['--auto', '--alert']):
        print(Colors.FAIL + f"[ERROR] {message}" + Colors.ENDC)
    sys.exit(1)

def success_msg(message, is_automated_call=False):
    """Menampilkan pesan sukses"""
    logger.info(message)
    if not is_automated_call:
        print(Colors.GREEN + f"[SUCCESS] {message}" + Colors.ENDC)

def info_msg(message, is_automated_call=False):
    """Menampilkan pesan info"""
    logger.info(message)
    if not is_automated_call:
        print(Colors.BLUE + f"[INFO] {message}" + Colors.ENDC)

def warning_msg(message, is_automated_call=False):
    """Menampilkan pesan peringatan"""
    logger.warning(message)
    if not is_automated_call:
        print(Colors.WARNING + f"[WARNING] {message}" + Colors.ENDC)

def load_config():
    """Memuat konfigurasi dari file config"""
    config = {}
    config_file = None
    
    # Cari config file yang ada
    for cf in CONFIG_FILES:
        if os.path.exists(cf):
            config_file = cf
            break
    
    if not config_file:
        error_exit(f"File konfigurasi tidak ditemukan di: {', '.join(CONFIG_FILES)}")
    
    try:
        with open(config_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if '=' in line:
                    line_content = line.split('#', 1)[0].strip()
                    if not line_content:
                        continue
                    parts = line_content.split('=', 1)
                    key = parts[0].strip()
                    value = parts[1].strip().strip('"\'')
                    
                    if key == "DYNAMIC_DIRS":
                        if value.startswith('(') and value.endswith(')'):
                            value_cleaned = value[1:-1].strip()
                            config[key] = [item.strip().strip('"\'') for item in value_cleaned.split()]
                        else:
                            logger.warning(f"Format DYNAMIC_DIRS tidak sesuai di config: {value}. Harusnya array bash.")
                            config[key] = []
                    else:
                        config[key] = value
        logger.info(f"Konfigurasi dimuat dari: {config_file}")
    except Exception as e:
        error_exit(f"Error membaca konfigurasi '{config_file}': {str(e)}")
    
    # Validasi kunci dasar yang selalu dibutuhkan
    required_keys_base = ["WEB_DIR", "PASSWORD", "MONITOR_IP", "MONITOR_USER", "REMOTE_GIT_BACKUP_PATH", "SSH_IDENTITY_FILE"]
    if config.get("BACKUP_DYNAMIC", "false").lower() == "true":
        required_keys_base.extend(["REMOTE_DYNAMIC_BACKUP_PATH", "LOCAL_DYNAMIC_RESTORE_CACHE_DIR", "DYNAMIC_DIRS"])

    missing_keys = [key for key in required_keys_base if key not in config or not config[key]]
    if missing_keys:
        error_exit(f"Variabel konfigurasi berikut hilang atau kosong di '{config_file}': {', '.join(missing_keys)}")
        
    return config

def verify_password_interactive(stored_password_b64):
    """Verifikasi password yang dimasukkan pengguna untuk mode interaktif"""
    try:
        password = getpass.getpass("Masukkan password restore: ")
        encoded_password = base64.b64encode(password.encode()).decode()
        
        if encoded_password != stored_password_b64:
            error_exit("Password salah!")
        return True
    except KeyboardInterrupt:
        error_exit("\nOperasi dibatalkan oleh pengguna.")
    except Exception as e:
        error_exit(f"Error saat verifikasi password: {str(e)}")

def create_pre_restore_backup(web_dir, is_automated_call=False):
    """Membuat backup dari keadaan saat ini sebelum restore."""
    try:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_target_dir = f"/tmp/web_content_prerestore_{timestamp}"
        info_msg(f"Membuat backup kondisi saat ini (sebelum restore) di: {backup_target_dir}", is_automated_call)
        
        # Menggunakan shutil.copytree untuk menyalin direktori
        shutil.copytree(web_dir, backup_target_dir, symlinks=True, dirs_exist_ok=True)

        success_msg(f"Backup kondisi pra-restore berhasil dibuat di {backup_target_dir}", is_automated_call)
        return backup_target_dir
    except Exception as e:
        warning_msg(f"Gagal membuat backup kondisi pra-restore: {str(e)}. Restore akan tetap dilanjutkan.", is_automated_call)
        return None

def get_commit_selection_interactive(repo, is_automated_call=False):
    """Interaktif meminta pengguna memilih commit atau otomatis jika auto mode."""
    try:
        commits = list(repo.iter_commits('master', max_count=20))
        if not commits:
            error_exit("Tidak ada commit yang tersedia di repository Git.")

        if is_automated_call:
            selected_commit = commits[1] if len(commits) > 1 else commits[0]
            info_msg(f"Mode otomatis: Memilih commit '{selected_commit.hexsha[:8]}' - {selected_commit.message.strip()}", is_automated_call)
            return selected_commit

        # Mode interaktif
        print("\n" + Colors.BOLD + "Daftar 20 commit terakhir (dari terbaru ke terlama):" + Colors.ENDC)
        print("======================================================")
        for i, commit in enumerate(commits):
            commit_time = datetime.datetime.fromtimestamp(commit.committed_date).strftime('%Y-%m-%d %H:%M:%S')
            print(f"{Colors.GREEN}{i+1}.{Colors.ENDC} [{commit_time}] {Colors.YELLOW}{commit.hexsha[:8]}{Colors.ENDC} - {commit.message.strip()}")
        
        while True:
            try:
                choice_str = input(Colors.BOLD + "\nPilih nomor commit untuk restore (default: 1 untuk terbaru, atau 2 untuk kedua terbaru): " + Colors.ENDC)
                if not choice_str:
                    choice = 1 
                else:
                    choice = int(choice_str)

                if 1 <= choice <= len(commits):
                    selected_commit = commits[choice-1]
                    break
                else:
                    print(Colors.WARNING + "Nomor tidak valid. Coba lagi." + Colors.ENDC)
            except ValueError:
                print(Colors.WARNING + "Masukkan nomor yang valid." + Colors.ENDC)
            except KeyboardInterrupt:
                error_exit("\nOperasi dibatalkan oleh pengguna.")
        
        commit_time_sel = datetime.datetime.fromtimestamp(selected_commit.committed_date).strftime('%Y-%m-%d %H:%M:%S')
        info_msg(f"Anda akan melakukan restore ke commit:\n  ID: {selected_commit.hexsha[:8]}\n  Pesan: {selected_commit.message.strip()}\n  Tanggal: {commit_time_sel}")
        confirm = input("Apakah Anda yakin ingin melanjutkan? (y/n): ")
        if confirm.lower() != 'y':
            error_exit("Operasi restore Git dibatalkan oleh pengguna.")
        return selected_commit
    except git.exc.GitCommandError as e:
        error_exit(f"Git error saat mengambil daftar commit: {str(e)}")
    except KeyboardInterrupt:
        error_exit("\nOperasi dibatalkan oleh pengguna.")


def restore_git_content(web_dir, selected_commit, is_automated_call=False):
    """Pulihkan konten web dari commit Git tertentu."""
    try:
        os.chdir(web_dir)
        repo = git.Repo(web_dir) 
        
        info_msg(f"Melakukan Git reset --hard ke commit: {selected_commit.hexsha[:8]}", is_automated_call)
        repo.git.reset('--hard', selected_commit.hexsha)
        
        info_msg("Membersihkan file yang tidak terlacak (git clean -fdx)...", is_automated_call)
        repo.git.clean('-fdx')
        
        success_msg(f"Konten Git berhasil dipulihkan ke commit {selected_commit.hexsha[:8]}", is_automated_call)
        return True
    except Exception as e:
        error_exit(f"Gagal melakukan restore Git: {str(e)}")

def fetch_dynamic_archives_from_remote(config, is_automated_call=False):
    """Mengambil arsip file dinamis dari server monitoring ke cache lokal."""
    info_msg("Memulai pengambilan arsip file dinamis dari server monitoring...", is_automated_call)
    
    monitor_ip = config['MONITOR_IP']
    monitor_user = config['MONITOR_USER']
    remote_path = config['REMOTE_DYNAMIC_BACKUP_PATH'].rstrip('/') + '/'
    local_cache_dir = config['LOCAL_DYNAMIC_RESTORE_CACHE_DIR']
    ssh_identity_file = config['SSH_IDENTITY_FILE']

    if not os.path.exists(local_cache_dir):
        try:
            os.makedirs(local_cache_dir, exist_ok=True)
            info_msg(f"Direktori cache restore dinamis dibuat: {local_cache_dir}", is_automated_call)
        except Exception as e:
            warning_msg(f"Gagal membuat direktori cache '{local_cache_dir}': {e}. Restore dinamis mungkin gagal.", is_automated_call)
            return False
    else:
        info_msg(f"Membersihkan cache restore dinamis lama di '{local_cache_dir}'...", is_automated_call)
        for item in os.listdir(local_cache_dir):
            item_path = os.path.join(local_cache_dir, item)
            try:
                if os.path.isfile(item_path) or os.path.islink(item_path): 
                    os.unlink(item_path)
                elif os.path.isdir(item_path): 
                    shutil.rmtree(item_path)
            except Exception as e:
                warning_msg(f"Gagal menghapus item cache lama '{item_path}': {e}", is_automated_call)

    if not shutil.which("rsync"):
        error_exit("'rsync' tidak ditemukan. Tidak dapat mengambil file dinamis.")
        return False

    rsync_cmd = [
        "rsync", "-avz", "--include=*.tar.gz", "--exclude=*",
        "-e", f"ssh -i {ssh_identity_file} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR",
        f"{monitor_user}@{monitor_ip}:{remote_path}",
        local_cache_dir
    ]
    info_msg(f"Menjalankan rsync untuk mengambil arsip dinamis...", is_automated_call)
    logger.debug(f"Perintah Rsync: {' '.join(rsync_cmd)}")
    try:
        process = subprocess.run(rsync_cmd, capture_output=True, text=True, check=False)
        if process.returncode == 0:
            success_msg("Rsync berhasil mengambil arsip dinamis ke cache lokal.", is_automated_call)
            return True
        else:
            logger.error(f"Rsync gagal dengan kode {process.returncode}. Stdout: {process.stdout}. Stderr: {process.stderr}")
            warning_msg(f"Rsync gagal mengambil arsip dinamis. Kode: {process.returncode}.", is_automated_call)
            return False
    except Exception as e:
        warning_msg(f"Error saat menjalankan rsync: {e}. Restore dinamis mungkin gagal.", is_automated_call)
        return False

def restore_dynamic_files_from_cache(config, is_automated_call=False):
    """Memulihkan file dinamis dari cache lokal yang sudah di-fetch."""
    if not config.get("BACKUP_DYNAMIC", "false").lower() == "true":
        info_msg("Restore file dinamis tidak diaktifkan dalam konfigurasi.", is_automated_call)
        return True

    info_msg("Memulai proses restore file dinamis dari cache lokal...", is_automated_call)
    web_dir = config['WEB_DIR']
    local_cache_dir = config['LOCAL_DYNAMIC_RESTORE_CACHE_DIR']
    dynamic_dirs_config = config.get('DYNAMIC_DIRS', [])

    if not dynamic_dirs_config:
        info_msg("Tidak ada DYNAMIC_DIRS yang dikonfigurasi untuk direstore.", is_automated_call)
        return True

    all_restored_successfully = True
    for dir_name_in_config in dynamic_dirs_config:
        archive_base_name = dir_name_in_config.replace('/', '_')
        archive_pattern = os.path.join(local_cache_dir, f"{archive_base_name}_*.tar.gz")
        found_archives = glob.glob(archive_pattern)

        if not found_archives:
            warning_msg(f"Tidak ada arsip backup ditemukan di cache untuk '{dir_name_in_config}'.", is_automated_call)
            continue

        latest_archive = max(found_archives, key=os.path.getmtime)
        target_path_for_dir = os.path.join(web_dir, dir_name_in_config)
        info_msg(f"Merestore '{dir_name_in_config}' dari arsip: '{os.path.basename(latest_archive)}'", is_automated_call)
        
        try:
            if os.path.lexists(target_path_for_dir):
                info_msg(f"Menghapus '{target_path_for_dir}' yang ada sebelum ekstraksi...", is_automated_call)
                if os.path.isdir(target_path_for_dir) and not os.path.islink(target_path_for_dir):
                    shutil.rmtree(target_path_for_dir)
                else:
                    os.unlink(target_path_for_dir)
            
            # Pastikan parent directory ada sebelum ekstraksi
            os.makedirs(os.path.dirname(target_path_for_dir), exist_ok=True)

            with tarfile.open(latest_archive, "r:gz") as tar:
                tar.extractall(path=web_dir)
            success_msg(f"Berhasil merestore '{dir_name_in_config}'.", is_automated_call)

            web_server_user = config.get('WEB_SERVER_USER')
            web_server_group = config.get('WEB_SERVER_GROUP')
            if web_server_user and web_server_group and os.path.exists(target_path_for_dir):
                try:
                    for dirpath, dirnames, filenames in os.walk(target_path_for_dir):
                        shutil.chown(dirpath, user=web_server_user, group=web_server_group)
                        for filename in filenames:
                            shutil.chown(os.path.join(dirpath, filename), user=web_server_user, group=web_server_group)
                    info_msg(f"Kepemilikan untuk '{target_path_for_dir}' diatur ke {web_server_user}:{web_server_group}", is_automated_call)
                except Exception as e_chown:
                    warning_msg(f"Gagal mengatur kepemilikan untuk '{target_path_for_dir}': {e_chown}", is_automated_call)
            
        except Exception as e:
            warning_msg(f"Gagal merestore '{dir_name_in_config}' dari '{latest_archive}': {e}", is_automated_call)
            all_restored_successfully = False
            
    if all_restored_successfully:
        success_msg("Restore file dinamis dari cache selesai.", is_automated_call)
    else:
        warning_msg("Beberapa file/direktori dinamis mungkin gagal direstore.", is_automated_call)
    return all_restored_successfully


def main():
    parser = argparse.ArgumentParser(description="SOC Recovery Phase Interactive Restore Tool - NIST 800-61")
    parser.add_argument("--alert", type=str, help="Data alert dari Wazuh dalam format JSON (untuk mode otomatis terbatas)")
    parser.add_argument("--commit", type=str, help="ID commit spesifik untuk restore (mode manual, akan tetap meminta konfirmasi)")
    parser.add_argument("--auto", action="store_true", help="Mode otomatis penuh: restore Git ke commit aman terakhir & restore dinamis jika aktif (melewati password & interaksi)")
    args = parser.parse_args()
    
    is_automated_call = args.auto or bool(args.alert)

    if not is_automated_call:
        print_banner()
    
    if os.geteuid() != 0 and not any(arg in sys.argv for arg in ['--non-root']):
        error_exit("Script ini umumnya perlu dijalankan sebagai root untuk operasi file sistem.")
            
    try:
        config = load_config()
    except SystemExit:
        sys.exit(1)
        
    web_dir = config['WEB_DIR']

    if not is_automated_call:
        verify_password_interactive(config['PASSWORD'])

    # Buat backup lokal dari kondisi saat ini SEBELUM melakukan restore apapun
    if not is_automated_call:
         create_pre_restore_backup(web_dir, is_automated_call)
    
    # 1. Restore Konten Statis dari Git
    info_msg(f"Memulai proses restore Git untuk direktori web: {web_dir}", is_automated_call)
    try:
        repo = git.Repo(web_dir)
    except git.exc.InvalidGitRepositoryError:
        error_exit(f"Repository Git tidak valid atau tidak ditemukan di {web_dir}.")
    except Exception as e_repo:
        error_exit(f"Gagal mengakses repository Git di {web_dir}: {e_repo}")

    selected_commit_obj = None
    if args.commit and not is_automated_call:
        try:
            selected_commit_obj = repo.commit(args.commit)
            info_msg(f"Commit spesifik '{args.commit}' akan digunakan setelah konfirmasi.", is_automated_call)
            commit_time_sel = datetime.datetime.fromtimestamp(selected_commit_obj.committed_date).strftime('%Y-%m-%d %H:%M:%S')
            info_msg(f"Akan melakukan restore ke commit spesifik:\n  ID: {selected_commit_obj.hexsha[:8]}\n  Pesan: {selected_commit_obj.message.strip()}\n  Tanggal: {commit_time_sel}", is_automated_call)
            if not is_automated_call:
                confirm = input("Apakah Anda yakin ingin melanjutkan dengan commit ini? (y/n): ")
                if confirm.lower() != 'y':
                    error_exit("Operasi restore Git dibatalkan oleh pengguna.")
        except Exception as e:
            error_exit(f"Commit ID '{args.commit}' tidak valid atau tidak ditemukan: {e}")
    else:
        selected_commit_obj = get_commit_selection_interactive(repo, is_automated_call)
    
    if not selected_commit_obj:
        error_exit("Gagal memilih commit untuk restore Git.")

    git_restore_success = restore_git_content(web_dir, selected_commit_obj, is_automated_call)
    if not git_restore_success:
        error_exit("Restore konten Git gagal. Proses dihentikan.")
    
    # 2. Restore File Dinamis
    dynamic_restore_success = True
    if config.get("BACKUP_DYNAMIC", "false").lower() == "true":
        if not is_automated_call:
            confirm_dynamic = input(Colors.BOLD + "\nApakah Anda ingin mencoba merestore file dinamis (misalnya, uploads, cache) dari backup terakhir? (y/n): " + Colors.ENDC)
            if confirm_dynamic.lower() != 'y':
                info_msg("Restore file dinamis dilewati oleh pengguna.", is_automated_call)
            else:
                if fetch_dynamic_archives_from_remote(config, is_automated_call):
                    dynamic_restore_success = restore_dynamic_files_from_cache(config, is_automated_call)
                else:
                    warning_msg("Gagal mengambil arsip dinamis dari remote. Restore file dinamis tidak dapat dilanjutkan.", is_automated_call)
                    dynamic_restore_success = False
        elif is_automated_call:
            info_msg("Mode otomatis: Mencoba restore file dinamis...", is_automated_call)
            if fetch_dynamic_archives_from_remote(config, is_automated_call):
                dynamic_restore_success = restore_dynamic_files_from_cache(config, is_automated_call)
            else:
                warning_msg("Gagal mengambil arsip dinamis dari remote (mode otomatis). Restore dinamis gagal.", is_automated_call)
                dynamic_restore_success = False

    if git_restore_success and dynamic_restore_success:
        success_msg("Proses restore (Git dan Dinamis jika dijalankan) selesai.", is_automated_call)
        if not is_automated_call:
            # Menampilkan statistik restore
            print("\n" + Colors.BOLD + "Statistik Restore Akhir:" + Colors.ENDC)
            print("------------------------")
            current_commit_info = repo.head.commit
            commit_time_info = datetime.datetime.fromtimestamp(current_commit_info.committed_date).strftime('%Y-%m-%d %H:%M:%S')
            print(f"Direktori web: {Colors.YELLOW}{web_dir}{Colors.ENDC}")
            print(f"Restore Git ke commit: {Colors.YELLOW}{current_commit_info.hexsha[:8]}{Colors.ENDC}")
            print(f"  Timestamp commit: {commit_time_info}")
            print(f"  Pesan commit: {current_commit_info.message.strip()}")
            print(f"Restore file dinamis: {Colors.GREEN if dynamic_restore_success else Colors.FAIL}{'Berhasil' if dynamic_restore_success else 'Gagal'}{Colors.ENDC}")
        sys.exit(0)
    else:
        error_msg = "Restore tidak selesai dengan sempurna."
        if not git_restore_success:
            error_msg += " Git restore gagal."
        if not dynamic_restore_success:
            error_msg += " Restore file dinamis gagal."
        error_exit(error_msg)


if __name__ == "__main__":
    main()
