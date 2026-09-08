import os
import sys

# Ensure repo root is on the import path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from web_app import app

client = app.test_client()

paths = ['/', '/config', '/upload', '/dashboard']
for p in paths:
    r = client.get(p)
    print(p, r.status_code)

r = client.post('/run-pipeline')
print('/run-pipeline', r.status_code)
