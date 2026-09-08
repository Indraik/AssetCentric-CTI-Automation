import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from wsgi import app


def test_routes():
    client = app.test_client()

    # Index page
    r = client.get("/")
    assert r.status_code == 200, f"Expected 200 on /, got {r.status_code}"

    # Config page redirects to index if not started
    r = client.get("/config")
    assert r.status_code == 302, f"Expected 302 on /config unstarted, got {r.status_code}"

    # API endpoints
    r = client.get("/api/live-stats" if "/api/live-stats" in [rule.rule for rule in app.url_map.iter_rules()] else "/live-stats")
    assert r.status_code == 200, f"Expected 200 on /live-stats, got {r.status_code}"
    data = r.get_json()
    assert "platform_stats" in data
    assert "dashboard" in data

    r = client.get("/pipeline-status")
    assert r.status_code == 200, f"Expected 200 on /pipeline-status, got {r.status_code}"
    p_data = r.get_json()
    assert "running" in p_data

    print("[+] test_routes passed successfully!")


if __name__ == "__main__":
    test_routes()
