import io
import os
import sys

# Ensure repo root is on the import path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from web_app import app

client = app.test_client()

# Start flow
res = client.post('/start', follow_redirects=True)
assert res.status_code == 200

# Submit config (enable firewall + edr optional)
res = client.post(
    '/config',
    data={
        'asset_type': 'postgresql',
        'critical_port': '5432',
        'asset_subnet': '192.168.1.0/24',
        'asset_host': 'db.internal.corp',
        'control_firewall': 'on',
        'control_edr': 'on',
    },
    follow_redirects=True,
)
assert res.status_code == 200
assert b'Upload Security Logs' in res.data

# Attempt upload missing firewall log (should show error)
res = client.post(
    '/upload',
    data={},
    content_type='multipart/form-data',
    follow_redirects=True,
)
assert b'Missing required uploads' in res.data

# Now include firewall log
res = client.post(
    '/upload',
    data={
        'firewall_log': (io.BytesIO(b'test'), 'firewall.log'),
    },
    content_type='multipart/form-data',
    follow_redirects=True,
)
assert res.status_code == 200
assert b'Upload successful' in res.data
assert b'Analyze Threat Intelligence' in res.data

print('workflow OK')
