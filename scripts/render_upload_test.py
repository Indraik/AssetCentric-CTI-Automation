import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from web_app import app

client = app.test_client()

with client.session_transaction() as sess:
    sess['config_done'] = True
    sess['asset_type'] = 'postgresql'
    sess['firewall'] = 'on'
    sess['edr'] = False
    sess['siem'] = False

response = client.get('/upload')
html = response.get_data(as_text=True)

if 'Firewall Logs' in html:
    print('has Firewall')
if 'EDR / Endpoint Logs' in html:
    print('has EDR')
if 'SIEM Logs' in html:
    print('has SIEM')
