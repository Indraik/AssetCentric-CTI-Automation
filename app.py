"""Compatibility entrypoint.

The project has been restructured into a modular Python Full Stack application.
The application factory is defined in `app/__init__.py`, and the WSGI runner is in `wsgi.py`.
This module is retained so existing scripts and commands importing `app` continue to work.
"""

import os
from wsgi import app

if __name__ == "__main__":
    port = int(os.getenv("PORT", "5050"))
    app.run(debug=True, host="127.0.0.1", port=port)