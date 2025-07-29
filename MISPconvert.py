from pymisp import ExpandedPyMISP, MISPEvent, MISPAttribute

# --- Konfigurasi MISP ---
misp_url = 'https://192.168.28.135'
misp_key = 'XweOnEWOtWFmIbW585H2m03R3SIZRmIKxrza73WB'
misp_verifycert = False

# --- Contoh sample_data (bebas kamu edit!) ---
sample_data = {
    'rule_id': '550',
    'file_path': '/var/www/html/webshell.php',
    'sha256': 'd2a537cb663d8f4fefb56410d4ebae7a1b16e63f9c9c3b57095a3938e0b1b6e3',
    'src_ip': '192.168.1.77',
    'url': 'http://example.com/hack.php'
}

# --- Koneksi ke MISP ---
misp = ExpandedPyMISP(misp_url, misp_key, misp_verifycert)

# --- Buat Event Baru ---
event = MISPEvent()
event.info = f"Percobaan Input Data Sample"
event.distribution = 0
event.threat_level_id = 2
event.analysis = 2
response = misp.add_event(event)
event_id = response['Event']['id']
print(f'Event berhasil dibuat dengan ID: {event_id}')

# --- Masukkan seluruh isi sample_data ke MISP ---
for key, value in sample_data.items():
    # Tipe attribute MISP bisa kamu tentukan sendiri di sini:
    # Bisa otomatis, bisa manual (misal: kunci 'sha256' pakai 'sha256', lain pakai 'text')
    if key == 'sha256':
        attr_type = 'sha256'
    elif key == 'src_ip':
        attr_type = 'ip-src'
    elif key == 'url':
        attr_type = 'url'
    elif key == 'file_path':
        attr_type = 'filename'
    else:
        attr_type = 'text'

    attr = MISPAttribute()
    attr.type = attr_type
    attr.value = value
    attr.category = 'Payload delivery'
    attr.comment = f'Data dari field {key}'
    attr.to_ids = True if attr_type in ['sha256', 'ip-src', 'url'] else False
    resp = misp.add_attribute(event_id, attr)
    if 'Attribute' in resp:
        print(f'Attribute {attr_type} ({value}) berhasil ditambahkan!')
    else:
        print(f'Gagal menambahkan attribute {attr_type}: {resp}')

