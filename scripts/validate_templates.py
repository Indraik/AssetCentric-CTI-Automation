import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from web_app import app

with app.test_request_context('/'):
    for tmpl in ['index.html', 'config.html', 'upload.html', 'dashboard.html']:
        try:
            app.jinja_env.get_template(tmpl).render()
            print('OK', tmpl)
        except Exception as e:
            print('ERROR', tmpl, e)
            raise
