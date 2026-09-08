import os
import sys
import traceback

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

try:
    from web_app import app
    print('Imported app successfully')
except Exception:
    traceback.print_exc()
    print('done', flush=True)
