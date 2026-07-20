# SOC Alert Triage & Enrichment Tool

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/yourusername/soc_triage_tool?style=social)](https://github.com/yourusername/soc_triage_tool)

**SOC Alert Triage & Enrichment Tool** is a modern Python GUI application designed to help SOC analysts quickly assess, enrich, and prioritize security alerts. It supports multiple alert sources (CSV, JSON, Splunk API), performs automated enrichment via free threat intelligence APIs (IP Geolocation, VirusTotal, AbuseIPDB), and generates professional triage reports.

---

## Table of Contents

- [Features](#features)
- [Screenshots](#screenshots)
- [Architecture](#architecture)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Configuration](#configuration)
- [Usage](#usage)
  - [Loading Alerts](#loading-alerts)
  - [Performing Enrichment](#performing-enrichment)
  - [Risk Scoring & Prioritization](#risk-scoring--prioritization)
  - [Generating Reports](#generating-reports)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgments](#acknowledgments)

---

## Features

- **Alert Ingestion** – Load alerts from CSV, JSON, or live Splunk searches.
- **Automated Enrichment** – Background threads enrich IPs via:
  - IP Geolocation (`ip-api.com`) – *free, no API key required*
  - VirusTotal IP reputation – *API key required (free tier available)*
  - AbuseIPDB IP check – *API key required (free tier available)*
- **Risk Scoring** – Composite risk score (0‑100) based on severity, enrichment results, and configurable weights.
- **Triage Workflow** – Mark alerts as Escalated, False Positive, Resolved, or Unreviewed. Add analyst notes.
- **Interactive GUI** – Built with Tkinter + ttkbootstrap for a dark, professional SOC‑tool feel.
  - Filterable, sortable alert table
  - Detail panel with raw log, enrichment output, and notes
  - Status bar with alert counts and enrichment progress
- **Caching** – SQLite cache to avoid repeated API calls for the same IP.
- **Reporting** – Export enriched alerts to CSV/JSON or generate a PDF triage report.
- **Extensible** – Abstract enricher class makes it easy to add new data sources (e.g., Shodan, AlienVault).

---

## Screenshots

*Coming soon – screenshots of the main window, enrichment results, and report generation.*

---

## Architecture
┌─────────────┐ ┌─────────────────┐ ┌──────────────────┐
│ Alert Source│─────>│ Alert Loader │─────>│ Alert Table (GUI)│
│ (CSV/JSON/ │ │ (data/.py) │ │ (gui/.py) │
│ Splunk) │ └─────────────────┘ └────────┬─────────┘
└─────────────┘ │
▼
┌─────────────────┐ ┌──────────────────┐
│ Enrichment │<──────────── Background ──│ Triage Actions │
│ Modules │ Threads │ (notes, status) │
│ (enrichment/.py)│ └──────────────────┘
└────────┬────────┘
│
▼
┌─────────────────┐ ┌───────────────────────┐
│ Risk Scorer │─────>│ Report Generator │
│ (utils/risk_) │ │ (reporting/*.py) │
└─────────────────┘ └───────────────────────┘

text

---

## Getting Started

### Prerequisites

- Python 3.10 or newer
- Git (to clone the repository)
- A VirusTotal API key (free tier: https://developers.virustotal.com/reference)
- An AbuseIPDB API key (free tier: https://www.abuseipdb.com/register?plan=free)
- (Optional) Splunk connection details if using Splunk as an alert source

### Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/yourusername/soc_triage_tool.git
   cd soc_triage_tool
Create a virtual environment (recommended):

bash
python -m venv venv
source venv/bin/activate   # Linux/macOS
venv\Scripts\activate      # Windows
Install dependencies:

bash
pip install -r requirements.txt
Set up configuration:

Copy the sample configuration file and fill in your API keys.

bash
cp config.ini.example config.ini
Edit config.ini with your VirusTotal and AbuseIPDB API keys. The IP Geolocation enricher (ip-api.com) works without any key.

Configuration
All settings are stored in config.ini. An example file looks like this:

ini
[API_KEYS]
virustotal = your_virustotal_api_key
abuseipdb = your_abuseipdb_api_key

[GENERAL]
theme = darkly
cache_enabled = True
cache_db_path = data/ip_cache.db
max_worker_threads = 10

[SPLUNK]
enabled = False
host = localhost
port = 8089
username = admin
password = your_splunk_password
You can also manage API keys through the GUI via Settings → API Keys.

Usage
Run the application:

bash
python main.py
Loading Alerts
Click the Load Data button in the toolbar.

Select the data source:

CSV File – browse and select a .csv file (a sample is provided in samples/sample_alerts.csv)

JSON File – select a .json file with alert data

Splunk Query – (if enabled) enter a Splunk saved search name and time range

Alerts will appear in the central table.

Performing Enrichment
Click Enrich All to enrich every visible alert (runs in background threads).

Select one or multiple alerts and click Enrich Selected.

Enrichment progress is shown in the status bar.

The following fields are added (when available):

IP Geolocation: Country, Region, City, ISP, Latitude, Longitude

VirusTotal: Malicious count, Suspicious count, Total scans

AbuseIPDB: Confidence score, Abuse reports, Last report date

Risk Scoring & Prioritization
The risk score is calculated automatically using configurable weights (defined in utils/risk_scorer.py). Alerts are color‑coded:

🔴 Critical (score ≥ 75)

🟠 High (score 50‑74)

🟡 Medium (score 25‑49)

🟢 Low (score 0‑24)

Generating Reports
Click Export Report to generate a PDF report of the currently selected alert(s). The report includes raw log, enrichment results, analyst notes, and risk score.

Use File → Export as CSV/JSON to save the enriched alert list for external analysis.

Project Structure
text
soc_triage_tool/
├── main.py                  # Application entry point
├── gui/
│   ├── main_window.py       # Main window layout (toolbar, paned windows)
│   ├── alert_table.py       # Treeview table with filtering & sorting
│   ├── detail_panel.py      # Right-side detail view for selected alert
│   ├── settings_dialog.py   # API key and configuration dialog
│   └── styles.py            # ttkbootstrap theme definitions
├── enrichment/
│   ├── base.py              # Abstract base class for all enrichers
│   ├── ip_geolocation.py    # ip-api.com geolocation enricher
│   ├── virustotal.py        # VirusTotal IP reputation enricher
│   └── abuseipdb.py         # AbuseIPDB IP check enricher
├── data/
│   ├── alert_loader.py      # CSV, JSON, and Splunk alert parsers
│   └── database.py          # SQLite cache for enrichment results
├── utils/
│   ├── config.py            # Configuration file reader/writer
│   ├── logger.py            # Logging setup (console + file)
│   └── risk_scorer.py       # Risk score calculation logic
├── reporting/
│   └── report_generator.py  # PDF and HTML report builder
├── samples/
│   └── sample_alerts.csv    # 10 sample alerts for testing
├── requirements.txt
├── config.ini               # Your local configuration (NOT committed)
├── config.ini.example       # Template without real API keys
└── README.md
Contributing
Contributions are welcome! If you'd like to add a new enrichment module, improve the GUI, or fix a bug:

Fork the repository.

Create a feature branch (git checkout -b feature/my-new-enricher).

Commit your changes with clear messages.

Push to your fork (git push origin feature/my-new-enricher).

Open a pull request against the main branch.

Please ensure your code follows the existing style and includes docstrings.

License
This project is licensed under the MIT License. See the LICENSE file for details.

Acknowledgments
ttkbootstrap – modern themed widgets for Tkinter

ip-api.com – free IP geolocation service

VirusTotal – file and IP reputation analysis

AbuseIPDB – IP address threat intelligence

TryHackMe SOC Level 1 – the foundational knowledge that inspired this project
