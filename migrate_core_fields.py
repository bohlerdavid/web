"""
Links existing section fields to core device columns so they display
real device data instead of '—'.
Run once: python migrate_core_fields.py
"""
import sqlite3, os

db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'devices.db')
db = sqlite3.connect(db_path)

mappings = {
    'seriennummer':  'serial_number',
    'betriebssystem':'operating_system',
    'kaufdatum':     'purchase_date',
    'garantie_bis':  'warranty_expiry',
    'ip_adresse':    'ip_address',
    'mac_adresse':   'mac_address',
    'cpu':           'cpu_info',
    'ram':           'ram_info',
    'hersteller':    'manufacturer',
    'modell':        'model',
    'notizen':       'notes',
}

updated = 0
for field_key, core_key in mappings.items():
    cur = db.execute(
        'UPDATE detail_fields SET core_field_key=? WHERE field_key=? AND (core_field_key IS NULL OR core_field_key="")',
        (core_key, field_key)
    )
    if cur.rowcount:
        print(f'  Verknüpft: {field_key} → {core_key}')
        updated += cur.rowcount

db.commit()
db.close()
print(f'\n{updated} Feld(er) verknüpft. Fertig!')
