"""Compatibility entrypoint.

The project has been restructured into a modular Python Full Stack application.
The application factory is defined in `app/__init__.py`, and the WSGI runner is in `wsgi.py`.
This module is retained for backward compatibility with existing scripts and commands.
"""

from wsgi import app

if __name__ == "__main__":
    app.run(debug=True, port=5000)