import io
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from wsgi import app


def test_full_workflow():
    client = app.test_client()

    # 1. Start flow
    res = client.post("/start", follow_redirects=True)
    assert res.status_code == 200, "Start flow failed"
    assert b"Configure Target Asset" in res.data or b"Asset Configuration" in res.data

    # 2. Submit config
    res = client.post(
        "/config",
        data={
            "asset_type": "postgresql",
            "critical_port": "5432",
            "asset_subnet": "192.168.1.0/24",
            "asset_host": "db.internal.corp",
            "control_firewall": "on",
            "control_edr": "on",
        },
        follow_redirects=True,
    )
    assert res.status_code == 200
    assert b"Upload Security Logs" in res.data

    # 3. Missing firewall log validation
    res = client.post(
        "/upload",
        data={},
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert b"Missing required uploads" in res.data

    # 4. Upload sample firewall log
    res = client.post(
        "/upload",
        data={
            "firewall_log": (io.BytesIO(b"timestamp,src_ip,dst_ip,action,threat_match\n2026-09-08 10:00:00,198.51.100.25,192.168.1.10,ALLOW,MATCHED_THREAT_FEED\n"), "firewall.log"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert res.status_code == 200
    assert b"Upload successful" in res.data or b"Logs uploaded successfully" in res.data
    assert b"Analyze Threat Intelligence" in res.data

    # 5. Run analyze-threat
    res = client.post("/analyze-threat", follow_redirects=True)
    assert res.status_code == 200
    assert b"Threat Score" in res.data or b"Dashboard" in res.data or b"SOC" in res.data

    print("[+] test_full_workflow passed successfully!")


if __name__ == "__main__":
    test_full_workflow()
