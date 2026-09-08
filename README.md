# AssetCentric Threat Intelligence Automation (CTI)

[![Live Demo](https://img.shields.io/badge/Live%20Demo-Render-00ff88?style=for-the-badge&logo=render&logoColor=0b111e)](https://cti-automation-platform.onrender.com/)
[![Python](https://img.shields.io/badge/Python-3.11-06b6d4?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.x-ffffff?style=for-the-badge&logo=flask&logoColor=0b111e)](https://flask.palletsprojects.com/)

> 🌐 **Live Application**: [https://cti-automation-platform.onrender.com/](https://cti-automation-platform.onrender.com/)

An asset-centric Cyber Threat Intelligence (CTI) web platform that collects external threat indicators, normalizes and enriches them, correlates them with uploaded internal security logs, and automatically generates enforcement-ready outputs (firewall blocklists, firewall rules, YARA rules, and correlation artifacts).

## Project Overview
This project implements a full CTI workflow with a professional SOC-style dashboard:

1. Configure target asset and enabled security controls.
2. Upload relevant logs (Firewall, SIEM/DNS, EDR/Endpoint).
3. Run threat intelligence collection and normalization.
4. Correlate uploaded logs against normalized indicators.
5. Generate output artifacts for enforcement and reporting.
6. Review live metrics and status in a dynamic dashboard.

## Key Features
- End-to-end CTI lifecycle automation.
- Integration with external threat feeds:
1. AbuseIPDB
2. URLHaus
3. ThreatFox
- Concurrent feed collection using worker threads.
- Indicator normalization with reliability scoring and severity mapping.
- Log correlation engine for IP/domain/hash matching.
- Fallback correlation support for sample logs marked with `threat_match=MATCHED_THREAT_FEED`.
- Automated output generation:
1. `outputs/firewall_blocklist.csv`
2. `outputs/firewall_rules.log`
3. `outputs/yara_rules.yar`
4. `outputs/correlation_results.json`
5. `outputs/unmatched_records.json`
- Two-stage Upload -> Analyze UX (upload does not auto-run pipeline).
- Dynamic cards and live polling (`/live-stats`) for Upload and Dashboard pages.
- Enhanced UI/UX with micro-interactions, loading states, and responsive layout.

## Technology Stack
- Backend: Flask (Python)
- Frontend: Jinja2 templates + CSS + lightweight vanilla JavaScript
- Data exchange: JSON + CSV
- Runtime: Python virtual environment (`.venv`)

## Repository Structure
Top-level directories and purpose:

- `app/`: Primary application package (Application Factory, Blueprints, Services, Engines, Templates, Static).
  - `app/core/`: Central configuration (`config.py`), structured logging (`logger.py`), and pipeline state (`state.py`).
  - `app/routes/`: Blueprint controllers (`views.py`, `analysis.py`, `api.py`, `downloads.py`).
  - `app/services/`: Application services (`asset_service`, `log_upload_service`, `threat_pipeline_service`, `correlation_service`, `stats_service`).
  - `app/engines/`: Domain engines:
    - `collectors/`: AbuseIPDB, URLHaus, and ThreatFox collectors.
    - `normalizer/`: Indicator normalization and IP geolocation enrichment.
    - `correlation/`: Multi-vector CSV log parsers and correlation engine.
    - `generators/`: Firewall blocklist, iptables rules, YARA rules, and risk engine.
  - `app/templates/`: Jinja2 templates (`index`, `config`, `upload`, `dashboard`, `base`).
  - `app/static/`: CSS styling and frontend assets.
- `storage/`: Isolated runtime directories (`data/`, `uploads/`, `outputs/`, `logs/`).
- `tests/`: Automated test suite (`test_templates.py`, `test_routes.py`, `test_workflow.py`).
- `wsgi.py`: WSGI entrypoint for development and production (`gunicorn wsgi:app`).
- `render.yaml`: Blueprint configuration for Render cloud deployment.

## Functional Workflow
### 1. Start Page (`/`)
- Resets session and presents platform capabilities + workflow overview.

### 2. Asset Configuration (`/config`)
- Captures:
1. Asset type
2. Critical port
3. Asset subnet
4. Hostname/IP
5. Enabled controls (Firewall, EDR, SIEM)
- Persists user settings to `storage/data/user_settings.json`.

### 3. Upload Logs (`/upload`)
- Validates required logs based on selected controls.
- Saves uploaded files into `storage/uploads/` and copies normalized names for correlation.
- Marks `logs_uploaded=True` and keeps user on upload page.
- Does not run intelligence automatically.

### 4. Analyze Threat Intelligence (`/analyze-threat`)
- Runs collector pipeline (`run_pipeline()`).
- Runs correlation (`run_correlation(user_config=...)`).
- Generates outputs and risk metadata.
- Redirects to dashboard on success.

### 5. Dashboard (`/dashboard`)
- Displays:
1. Feed metrics
2. Threat score
3. Correlation status
4. Pipeline status
5. Top indicators
6. Generated control actions
- Auto-refreshes live cards through polling from `/live-stats`.

## Data Flow Summary
1. Collectors fetch raw indicators -> `storage/data/raw_threat_feed.json`.
2. Normalizer groups and enriches indicators -> `storage/data/normalized_threat_feed.json`.
3. Uploaded logs are parsed from `storage/uploads/*.csv`.
4. Correlation engine compares indicators vs logs.
5. Correlation payload -> `storage/outputs/correlation_results.json`.
6. Rule generators derive firewall/YARA/enforcement artifacts into `storage/outputs/`.

## Core Modules
### Threat Intelligence Layer
- `app/services/threat_pipeline_service.py`: Runs AbuseIPDB, URLHaus, ThreatFox collectors concurrently.
- `app/engines/normalizer/normalizer.py`: Normalizes indicators, assigns confidence/severity, enriches IP metadata.

### Correlation Layer
- `app/engines/correlation/log_parser.py`: Parses firewall, DNS, endpoint CSV logs.
- `app/engines/correlation/correlation_engine.py`: Matches indicators across IP, domain, and hash dimensions.

### Automation Layer
- `app/services/correlation_service.py`: Orchestrates correlation and artifact generation.
- `app/engines/generators/blocklist_generator.py`: Builds deduplicated blocklist (critical/high/medium severity).
- `app/engines/generators/iptables_generator.py`: Emits iptables rules from blocklist.
- `app/engines/generators/yara_generator.py`: Emits YARA rules from matched hashes.

## API and Route Reference
Main user routes:

- `GET /` -> Landing page
- `POST /start` -> Start new analysis session
- `GET|POST /config` -> Asset + control configuration
- `GET|POST /upload` -> Log upload + validation
- `POST /analyze-threat` -> Pipeline + correlation execution
- `GET /dashboard` -> Final review dashboard

Status and live data routes:

- `GET /pipeline-status` -> Background pipeline state
- `GET /live-stats` -> Upload/dashboard polling payload

Download routes:

- `GET /download/blocklist`
- `GET /download/yara`
- `GET /download/correlation`
- `GET /download/threat-feed`
- `GET /download/raw-feed`

## Setup and Run
### Prerequisites
- Python 3.10+
- Virtual environment support

### Installation
```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

### Environment variables
Set these before running the app:

```powershell
$env:ABUSEIPDB_API_KEY = "your-real-abuseipdb-api-key"
$env:FLASK_SECRET_KEY = "replace-with-a-random-secret"
```

### Start Application
```powershell
python wsgi.py
```
*(Or via backward-compatibility wrapper: `python web_app.py`)*

### Run Automated Tests
```powershell
python tests/test_templates.py
python tests/test_routes.py
python tests/test_workflow.py
```

## Configuration
### API keys
- Centralized in `app/core/config.py`.
- Reads AbuseIPDB API key from the `ABUSEIPDB_API_KEY` environment variable.

Recommended improvement:
- Move secrets to environment variables and never commit real keys.

Example approach:
```python
import os
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "ABUSEIPDB_API_KEY_PLACEHOLDER")
```

### How to get an AbuseIPDB API key
1. Create or sign in to your AbuseIPDB account.
2. Open the account API page: `https://www.abuseipdb.com/account/api`
3. Generate a new API key from the dashboard.
4. Copy the key and set it in your shell before starting the app.

PowerShell example:

```powershell
$env:ABUSEIPDB_API_KEY = "paste-your-generated-key-here"
$env:FLASK_SECRET_KEY = "replace-with-a-random-secret"
.venv\Scripts\python.exe web_app.py
```

If `ABUSEIPDB_API_KEY` is left as the placeholder value, the AbuseIPDB collector is skipped automatically.

### GitHub publishing checklist
- Do not commit real API keys or production secrets.
- Initialize Git and verify ignored files before the first commit.
- Keep `.venv/`, generated outputs, uploaded logs, and runtime caches out of the repository.

Example commands:

```powershell
git init
git add .
git status
git commit -m "Initial commit"
git branch -M main
git remote add origin https://github.com/<your-user>/<your-repo>.git
git push -u origin main
```

## Deployment to Render

The application is deployed and live on Render:
👉 **[https://cti-automation-platform.onrender.com/](https://cti-automation-platform.onrender.com/)**

### Option 1: Blueprints (Recommended)
This repository includes a `render.yaml` blueprint file that automatically configures the web service on Render.
1. Connect your GitHub account to Render.
2. Select **Blueprints** from the Render Dashboard.
3. Click **New Blueprint Instance** and select your repository (`Indraik/AssetCentric-CTI-Automation`).
4. Render will read the `render.yaml` configuration and deploy the app automatically.
5. In the Render Dashboard, you can configure your `ABUSEIPDB_API_KEY` environment variable if desired.

### Option 2: Manual Deployment
If you prefer to configure the Web Service manually:
1. Create a new **Web Service** on Render.
2. Link your Git repository.
3. Use the following settings:
   - **Environment**: `Python`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn wsgi:app` (or `gunicorn app:app`)
4. In the **Environment** settings of the service, add the following variables:
   - `PYTHON_VERSION`: `3.11.9`
   - `FLASK_SECRET_KEY`: A secure random secret key (generated automatically or via Render).
   - `ABUSEIPDB_API_KEY`: (Optional) Your AbuseIPDB API key.

## Output Artifacts
After successful analysis:

- `outputs/firewall_blocklist.csv`: IP/action mapping for blocklist import.
- `outputs/firewall_rules.log`: iptables-ready DROP rules.
- `outputs/yara_rules.yar`: Matched hash-based YARA rules.
- `outputs/correlation_results.json`: Full correlation payload + metadata.
- `outputs/unmatched_records.json`: Non-matching logs for review.

## UI/UX Highlights
- SOC-inspired visual language across all pages.
- Dynamic cards bound to runtime data, not static placeholders.
- Upload page loading indicator and controlled two-stage workflow.
- Polling-based live updates for key metrics and status.
- Micro-interactions:
1. Focus-visible accessibility states
2. Card hover depth and shimmer
3. Reveal-on-scroll animation with reduced-motion fallback

## Troubleshooting
### App exits on startup
Common cause: missing dependencies.

Fix:
```powershell
.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### Empty firewall or YARA outputs
Possible causes:
1. No matching indicators in uploaded logs
2. Endpoint hash logs not provided for YARA
3. Feed/log format mismatch

Checks:
- Verify `uploads/firewall_logs.csv` and/or `uploads/endpoint_logs.csv` are non-empty.
- Inspect `outputs/correlation_results.json` for `MATCH` records.

### Template validation errors
- Run `template_render_validation.py` with project venv interpreter.

Compatibility wrappers are retained for transition:
- `app.py` -> forwards to `web_app.py`
- `validate_templates.py` -> forwards to `template_render_validation.py`
- `test_run.py` -> forwards to `threat_pipeline_smoke_runner.py`

## Current Status
The project currently supports:
- Stable end-to-end flow from upload to generated artifacts.
- Data-driven metrics and live dashboard updates.
- Strong baseline UI/UX for SOC demo and practical workflow validation.

## Future Enhancements
- Full API key management via `.env` and secret vault practices.
- Real-time websocket updates instead of polling.
- Pagination and advanced filters for indicator/correlation tables.
- Exportable PDF risk report generation.
- Automated unit and integration test coverage for all pipeline stages.
How to run this project
Open a terminal in:

Cyber-Threat-Intelligence-Platform
Create and activate a Python virtual environment:

python -m venv .venv
.\.venv\Scripts\Activate.ps1


Install dependencies:
pip install -r requirements.txt

Set required environment variables:

$env:ABUSEIPDB_API_KEY = "your-real-abuseipdb-api-key"
$env:FLASK_SECRET_KEY = "replace-with-a-random-secret"

Start the app:

.\.venv\Scripts\python.exe web_app.py

Open your browser at:

http://127.0.0.1:5000/
Notes