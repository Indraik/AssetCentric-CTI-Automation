import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from web_app import app
from flask import session
import json
from config.settings import NORMALIZED_FEED_PATH

with app.test_request_context('/dashboard'):
    session['analysis_done'] = True
    session['asset_type'] = 'postgresql'
    session['port'] = '5432'
    session['subnet'] = '192.168.1.0/24'
    session['host'] = 'db.internal'
    session['firewall'] = 'on'
    session['edr'] = 'on'
    session['siem'] = 'on'

    os.makedirs(os.path.dirname(NORMALIZED_FEED_PATH), exist_ok=True)
    with open(NORMALIZED_FEED_PATH, 'w') as f:
        json.dump([{
            'indicator': '1.1.1.1',
            'type': 'ip',
            'severity': 'high',
            'confidence': 'high',
            'reliability_score': 72,
            'sources': ['abuseipdb'],
            'country': 'US',
            'asn': 'AS123'
        }], f)

    html = app.jinja_env.get_template('dashboard.html').render(
        metrics={'indicators': 1, 'high_confidence': 1, 'suspicious_ips': 1, 'domains': 0, 'risk': 'HIGH', 'total_logs': 1},
        indicators=[{
            'indicator': '1.1.1.1',
            'type': 'ip',
            'severity': 'high',
            'confidence': 'high',
            'reliability_score': 72,
            'sources': ['abuseipdb'],
            'country': 'US',
            'asn': 'AS123'
        }],
        sources=['abuseipdb'],
        pipeline_last_run='2026-03-09T21:00:00',
        trends={'indicators': {'direction': 'up', 'label': '↑ +1'}, 'high_confidence': {'direction': 'up', 'label': '↑ +1'}, 'suspicious_ips': {'direction': 'up', 'label': '↑ +1'}},
        threat_score=42,
        risk_meta={'icon': '🔴', 'label': 'Active threat indicators detected', 'color': 'red'},
        distribution={'ip': 1, 'domain': 0, 'hash': 0, 'url': 0},
        timeline=[{'ts': '10:31', 'message': 'Indicator collected'}]
    )

    print('rendered', len(html))
