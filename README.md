# SOC Alert Triage & Enrichment Tool

A complete, advanced **Security Operations Center (SOC)** alert triage and enrichment tool with a polished dark-themed GUI. Built for analysts who need to quickly assess, enrich, prioritize, and document security alerts coming from a SIEM (Splunk) or any CSV/JSON export.

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![GUI](https://img.shields.io/badge/GUI-tkinter%20%2B%20ttkbootstrap-orange)
![License](https://img.shields.io/badge/license-MIT-green)

---

## Table of Contents

1. [Features](#features)
2. [Architecture](#architecture)
3. [Quick Start](#quick-start)
4. [Configuration](#configuration)
5. [Obtaining API Keys](#obtaining-api-keys)
6. [Using the Tool](#using-the-tool)
7. [Project Structure](#project-structure)
8. [Extending — Adding a New Enricher](#extending--adding-a-new-enricher)
9. [Troubleshooting](#troubleshooting)
10. [Roadmap](#roadmap)

---

## Features

### Core capabilities

- **Multi-source alert ingestion**
  - CSV file (any column order — common aliases auto-detected)
  - JSON file (array of objects or `{"alerts": [...]}`)
  - Splunk REST API (saved-search polling via bearer token or basic auth)
- **Automated enrichment** (background-threaded, GUI never freezes)
  - **IP geolocation** via `ip-api.com` — *no API key required*
  - **VirusTotal** v3 IP reputation — malicious engine count
  - **AbuseIPDB** v2 — confidence score, abuse categories, total reports
- **Risk scoring & prioritization**
  - Composite 0-100 score from severity + enrichment signals
  - Configurable weights and tier thresholds (in `config.ini` / Settings UI)
  - Color-coded rows: Red (Critical) / Orange (High) / Yellow (Medium) / Green (Low)
- **Triage actions**
  - Mark alerts as *Escalated / False Positive / Resolved / Unreviewed*
  - Per-alert analyst notes (auto-saved on the alert object)
  - Filter by status, severity, min risk score, country, source IP
- **Reporting**
  - **PDF** triage report (via ReportLab) — summary table + per-alert detail
  - **HTML** triage report (dark theme, shareable)
  - **Ticket creation stub** (TheHive / ServiceNow — wire in your own API call)
- **Export**
  - Enriched alerts to CSV or JSON (round-trips all original + enrichment fields)
- **Caching**
  - SQLite cache (`data/enrichment_cache.db`) for IP enrichment results
  - Configurable TTL (default 24h, set to `0` for forever)
  - Cache stats visible in the filter panel
- **Robustness**
  - Exponential backoff on API rate limits (HTTP 429) and 5xx errors
  - All actions logged to `logs/soc_tool.log` (rotating, 5 MB × 5)
  - Non-blocking error dialogs (GUI keeps working)
  - Thread-safe UI updates via a `queue.Queue`
- **Polished dark UI** (ttkbootstrap `cyborg` theme, SOC-inspired palette)

---

## Architecture

The project follows a clean **layered architecture** so each concern is
isolated and testable:

```
                  ┌─────────────────────────────────┐
                  │           gui /                  │  Tkinter + ttkbootstrap
                  │   main_window  alert_table       │  (presentation layer)
                  │   detail_panel settings_dialog   │
                  │   styles                         │
                  └─────────────┬───────────────────┘
                                │  calls
                                ▼
                  ┌─────────────────────────────────┐
                  │  enrichment /                    │  External API wrappers
                  │   base  ip_geolocation           │  (with retry + cache)
                  │   virustotal  abuseipdb          │
                  └─────────────┬───────────────────┘
                                │  uses
                  ┌─────────────▼───────────────────┐
                  │  data /                          │  Loaders + SQLite cache
                  │   alert_loader database          │
                  └─────────────┬───────────────────┘
                                │  uses
                  ┌─────────────▼───────────────────┐
                  │  utils /  reporting /            │  Cross-cutting concerns
                  │   config logger risk_scorer      │  (config, logging, scoring,
                  │   report_generator               │   report generation)
                  └─────────────────────────────────┘
```

### Key design decisions

1. **Alert is a single dataclass** (`data/alert_loader.py`). All loaders
   normalize their input into `Alert` instances so the rest of the
   application is source-agnostic.
2. **Enrichers share a common base** (`enrichment/base.py`). The
   `BaseEnricher.enrich()` template method handles caching, retries,
   backoff, and uniform error handling — subclasses only implement
   `_fetch()`.
3. **Threaded enrichment with UI queue**. Worker threads call
   `enricher.enrich()` and push results onto a `queue.Queue`. The GUI
   thread polls the queue every 100 ms via `root.after()` and applies
   updates — this is the canonical Tkinter-safe pattern.
4. **Configuration in `config.ini`**. No API keys are ever hardcoded;
   they are edited via the Settings dialog and persisted to disk.
5. **SQLite cache is thread-safe**. A single connection is shared, with
   a `threading.Lock` serializing all writes.
6. **Risk scoring is configurable**. Weights and thresholds live in
   `config.ini`; changing them in the Settings dialog takes effect
   immediately (the scorer is re-instantiated and all alerts are
   re-scored).

---

## Quick Start

### 1. Install Python

Python **3.10 or newer** is required. Verify with:

```bash
python --version
```

On Linux you may also need the Tk bindings:

```bash
sudo apt-get install python3-tk
```

### 2. Install dependencies

```bash
cd soc_triage_tool
pip install -r requirements.txt
```

### 3. Run the tool

```bash
python main.py
```

The window opens and **automatically loads `samples/sample_alerts.csv`**
(15 alerts — mix of internal/external IPs, different severities). You
can immediately:

- Click an alert → see details on the right panel
- Click **Batch Enrich All** → IP geolocation runs instantly (no key
  needed); VT and AbuseIPDB are skipped if their keys aren't set yet
- Click **Settings → API Keys** → add your VirusTotal / AbuseIPDB keys,
  click **Save**, then click **Batch Enrich All** again to fetch full
  reputation data
- Click **PDF Report** or **HTML Report** → generates a triage report
  for all visible (filtered) alerts

---

## Configuration

All configuration is in **`config.ini`** at the project root. The file
is created automatically with sensible defaults the first time you run
the tool. You can edit it either:

- **Through the GUI**: `Settings` button in the toolbar → dialog with
  tabs for *API Keys*, *Splunk*, *Risk Scoring*.
- **By hand**: any text editor.

### Sections

| Section        | Keys                                                                 | Notes                                                            |
| -------------- | -------------------------------------------------------------------- | ---------------------------------------------------------------- |
| `[api_keys]`   | `virustotal`, `abuseipdb`                                            | Free API keys — see below.                                       |
| `[endpoints]`  | `ip_api`, `virustotal`, `abuseipdb`, `splunk`                        | Override only if you have a commercial endpoint.                 |
| `[splunk]`     | `username`, `password`, `bearer_token`, `saved_search`, `verify_ssl`| Bearer token takes precedence over basic auth.                   |
| `[scoring]`    | `severity_weight`, `vt_malicious_weight`, `abuseipdb_weight`, `geolocation_weight` | Weights are normalized automatically.            |
| `[thresholds]` | `critical`, `high`, `medium`, `low`                                  | Lower bounds for each tier (must be descending).                 |
| `[cache]`      | `ttl_hours`                                                          | `0` = cache forever.                                             |
| `[ui]`         | `theme`, `window_width`, `window_height`                             | Window size is auto-saved on close.                              |

---

## Obtaining API Keys

### VirusTotal (free)

1. Go to <https://www.virustotal.com/gui/sign-up>
2. Create a free account.
3. Sign in and visit <https://www.virustotal.com/gui/my-apikey>
4. Copy your API key (64-character hex string).
5. Paste it into **Settings → API Keys → VirusTotal**.

> **Free-tier limits**: 4 requests/minute, 500/day. The tool's
> exponential-backoff retry handles `429` responses, but for very large
> alert sets you may want a paid key.

### AbuseIPDB (free)

1. Go to <https://www.abuseipdb.com/account/register>
2. Create a free account.
3. After email verification, visit <https://www.abuseipdb.com/account/api>
4. Click **Create Key** and copy it.
5. Paste it into **Settings → API Keys → AbuseIPDB**.

> **Free-tier limits**: 1,000 checks/day.

### ip-api.com (no key)

The free endpoint is used by default; it requires **no key** and works
out of the box. Limits: 45 req/min from the same IP, HTTP only. For
HTTPS or higher limits, purchase a commercial key from
<https://members.ip-api.com/>.

---

## Using the Tool

### Loading alerts

| Button                | Action                                                |
| --------------------- | ----------------------------------------------------- |
| **Load CSV**          | Open a file dialog and load a CSV.                    |
| **Load JSON**         | Open a JSON file (array or `{"alerts":[...]}`).       |
| **Load from Splunk**  | Poll the configured Splunk saved search.              |
| *(auto)*              | On startup, `samples/sample_alerts.csv` is auto-loaded.|

The loader accepts many common column aliases (`src`, `source_ip`,
`srcip`; `severity`, `priority`, `level`; etc.). See
`data/alert_loader.py → COLUMN_ALIASES` for the full list.

### Enriching alerts

- **Enrich Selected**: enriches only the alert currently selected in
  the table.
- **Batch Enrich All**: enriches all *visible* (post-filter) alerts
  that have a source IP and are not yet enriched. Runs concurrently
  (max 3 workers) to stay within API rate limits.
- A progress bar in the bottom status bar shows batch progress.
- The SQLite cache means re-enriching the same IP is instant and free.

### Triage actions

- Select an alert → the right panel shows full detail.
- Use the **Status** dropdown or the quick-action buttons
  (**Escalate / False Positive / Resolve**).
- Type in the **Analyst Notes** text box — auto-saved (500 ms
  debounce) to the alert object.

### Filtering

The left panel offers five filters, all applied live:

- Status (dropdown)
- Severity (dropdown)
- Min Risk Score (slider, 0-100)
- Country contains (text)
- Source IP contains (text)

Click **Reset Filters** to clear them.

### Reporting & export

- **Export CSV / Export JSON**: writes all loaded alerts (with
  enrichment + triage fields) to a file.
- **PDF Report**: generates a polished landscape PDF with a summary
  table and per-alert detail pages.
- **HTML Report**: generates a dark-themed HTML report (viewable in
  any browser, easy to email).
- **Create Ticket (stub)**: appends a fake ticket ID to the alert's
  notes — see *Roadmap* below.

---

## Project Structure

```
soc_triage_tool/
├── main.py                  # Entry point — runs `python main.py`
├── config.ini               # API keys, weights, thresholds (auto-created)
├── requirements.txt
├── README.md                # This file
│
├── gui/                     # Tkinter + ttkbootstrap UI
│   ├── __init__.py
│   ├── main_window.py       # Top-level controller (toolbar, body, status bar)
│   ├── alert_table.py       # Sortable, color-coded Treeview
│   ├── detail_panel.py      # Right-side detail + triage actions panel
│   ├── settings_dialog.py   # API keys + scoring config dialog
│   └── styles.py            # SOC palette, ttkbootstrap theme overlay
│
├── enrichment/              # External API wrappers
│   ├── __init__.py
│   ├── base.py              # Abstract BaseEnricher (cache + retry + backoff)
│   ├── ip_geolocation.py    # ip-api.com (free, no key)
│   ├── virustotal.py        # VirusTotal v3
│   └── abuseipdb.py         # AbuseIPDB v2
│
├── data/                    # Loaders + cache
│   ├── __init__.py
│   ├── alert_loader.py      # CSV / JSON / Splunk → list[Alert]
│   └── database.py          # Thread-safe SQLite enrichment cache
│
├── utils/                   # Cross-cutting
│   ├── __init__.py
│   ├── config.py            # ConfigManager (configparser wrapper)
│   ├── logger.py            # Rotating file + console logger
│   └── risk_scorer.py       # Composite 0-100 risk score
│
├── reporting/
│   ├── __init__.py
│   └── report_generator.py  # PDF + HTML generators + ticket stub
│
├── samples/
│   └── sample_alerts.csv    # 15 dummy alerts for immediate testing
│
├── logs/                    # soc_tool.log (auto-created)
└── reports/                 # Generated PDF/HTML reports land here
```

---

## Extending — Adding a New Enricher

Adding a new enrichment source is a 3-step process:

### Step 1 — Subclass `BaseEnricher`

Create `enrichment/my_source.py`:

```python
from typing import Any, Dict
from enrichment.base import BaseEnricher
from utils.config import ConfigManager
from data.database import EnrichmentCache
import requests

class MySourceEnricher(BaseEnricher):
    name = "my_source"             # cache key + log label
    requires_api_key = True        # or False

    def __init__(self, config, cache, session=None):
        super().__init__(config, cache, session)
        self._endpoint = config.get_endpoint("my_source")

    def _fetch(self, ip: str) -> Dict[str, Any]:
        resp = self.session.get(
            f"{self._endpoint}{ip}",
            headers={"Authorization": f"Bearer {self._get_api_key()}"},
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json()  # normalized dict
```

That's all — caching, retries, exponential backoff, and error handling
are handled by `BaseEnricher.enrich()`.

### Step 2 — Register it in the GUI

Edit `gui/main_window.py → _enrich_alert()` and add:

```python
if self.config.get_api_key("my_source"):
    enrichers.append(MySourceEnricher(self.config, self.cache, session))
```

…and merge the result fields in `_merge_enrichment()`.

### Step 3 — Add config keys

Append to `config.ini`:

```ini
[api_keys]
my_source = your_key_here

[endpoints]
my_source = https://api.example.com/v1/ip/
```

Optionally expose the key in `gui/settings_dialog.py` (add an
`Entry` bound to a `StringVar`, then `config.set_api_key("my_source", var.get())`).

### Step 4 — Use the new field in risk scoring (optional)

If you want the new signal to affect the risk score, edit
`utils/risk_scorer.py` to add a new component (e.g.
`my_source_to_score(...)`) and include it in the weighted sum. Add a
matching weight key to `config.ini` under `[scoring]`.

---

## Troubleshooting

| Symptom                                                  | Likely cause / fix                                                                                  |
| -------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| Window doesn't open, error mentioning `tkinter`          | On Linux: `sudo apt-get install python3-tk`                                                          |
| Buttons look unstyled (plain grey)                       | `ttkbootstrap` not installed. Run `pip install ttkbootstrap`.                                       |
| Enrichment returns "requires an API key"                 | Open Settings → API Keys, paste your key, click Save.                                               |
| Enrichment returns `HTTP 429 Too Many Requests`          | You hit a rate limit. The tool retries with backoff; for large batches, add a paid API key or wait. |
| Splunk load fails with SSL error                         | Set `verify_ssl = false` in `[splunk]` (development only!).                                         |
| `reportlab` import error on PDF generation               | `pip install reportlab`. HTML reports work without it.                                              |
| Logs not appearing                                       | Check `logs/soc_tool.log`. Logging is initialized in `main.py`.                                     |
| Cached results look stale                                | Click **Clear Cache** in the toolbar, or lower `[cache]/ttl_hours` in `config.ini`.                 |

For anything else, check `logs/soc_tool.log` — all actions and errors
are logged with timestamps and thread names.

---

## Roadmap

- **Real ticketing integration** — replace `create_ticket_stub()` in
  `reporting/report_generator.py` with a real call to TheHive's
  `/api/v1/alert` or ServiceNow's `/api/now/table/incident`.
- **Splunk real-time polling** — wrap `_on_load_splunk()` in a
  configurable interval scheduler (the existing thread infrastructure
  supports this; only a "Start polling" toggle is needed).
- **More enrichers** — Shodan, GreyNoise, AlienVault OTX, URLscan.io
  (follow the 3-step guide above).
- **User authentication / multi-analyst** — currently single-user;
  could add per-analyst notes and triage state with a small schema
  upgrade to the SQLite DB.
- **Interactive charts** — risk-tier distribution, top-source-IP
  bar chart, etc. (could use `matplotlib` embedded in a Tk frame).

---

## License

MIT — see source headers. Use it, fork it, extend it.
