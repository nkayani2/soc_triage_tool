"""Alert loaders for the SOC Triage Tool.

Supports three ingestion modes:

1. **CSV** — any flat alert export (Splunk ``| outputcsv``, SIEM report).
2. **JSON** — either a JSON array of alert objects or ``{"alerts": [...]}``.
3. **Splunk** — saved-search polling via the Splunk REST API.

The loader normalizes all input formats into a list of
:class:`Alert` dataclass instances so the rest of the application does
not need to care where the data came from.
"""

from __future__ import annotations

import csv
import json
import re
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

from utils.config import ConfigManager
from utils.logger import get_logger

logger = get_logger(__name__)

# Very small IPv4 regex — enough for our purposes (we don't need strict
# RFC validation; if it looks like an IP we send it to the enrichers).
_IPV4_RE = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$")


def looks_like_ip(value: Any) -> bool:
    """Return True if ``value`` is a string that looks like an IPv4 address."""
    if not isinstance(value, str):
        return False
    return bool(_IPV4_RE.match(value.strip()))


# ---------------------------------------------------------------------- #
# Alert dataclass
# ---------------------------------------------------------------------- #
@dataclass
class Alert:
    """Normalized representation of a single SIEM alert.

    The first six fields are the "core" columns shown in the GUI table.
    The remaining fields are populated by the enrichment pipeline and
    by analyst triage actions.
    """

    # Core fields (always present after loading).
    timestamp: str = ""
    source_ip: str = ""
    destination_ip: str = ""
    alert_name: str = ""
    severity: str = ""
    raw_log: str = ""

    # Enrichment results (filled in by the enrichers).
    country: str = ""
    isp: str = ""
    vt_malicious: Optional[int] = None
    abuseipdb_confidence: Optional[int] = None
    abuseipdb_category: str = ""

    # Triage state (analyst-driven).
    status: str = "Unreviewed"
    notes: str = ""
    risk_score: int = 0
    risk_tier: str = "Low"

    # Bookkeeping.
    alert_id: str = ""
    enriched: bool = False
    enrichment_errors: List[str] = field(default_factory=list)

    # The full original row (for round-tripping to CSV/JSON exports).
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a flat dict suitable for CSV/JSON export."""
        d = asdict(self)
        # Drop the helper-only `extra` after merging its keys back in.
        extra = d.pop("extra", {}) or {}
        # Don't let extra keys overwrite canonical fields.
        for k, v in extra.items():
            if k not in d:
                d[k] = v
        return d


# ---------------------------------------------------------------------- #
# Column-name resolution
# ---------------------------------------------------------------------- #
# Map canonical field -> list of accepted source column names (case-insensitive).
COLUMN_ALIASES: Dict[str, List[str]] = {
    "timestamp": ["timestamp", "time", "_time", "date", "eventtime", "datetime"],
    "source_ip": ["source_ip", "src_ip", "srcip", "sourceip", "src", "source", "client_ip"],
    "destination_ip": ["destination_ip", "dest_ip", "dst_ip", "dstip", "destinationip", "dst", "destination"],
    "alert_name": ["alert_name", "alertname", "name", "title", "rule_name", "signature", "event_type"],
    "severity": ["severity", "priority", "level", "risk_level", "urgency"],
    "raw_log": ["raw_log", "rawlog", "raw", "message", "log", "event", "_raw"],
    "alert_id": ["alert_id", "id", "event_id", "uuid"],
}


def _resolve_column(headers: List[str], canonical: str) -> Optional[str]:
    """Find the actual header that corresponds to ``canonical``."""
    lowered = [h.strip().lower() for h in headers]
    for alias in COLUMN_ALIASES.get(canonical, []):
        if alias in lowered:
            return headers[lowered.index(alias)]
    return None


# ---------------------------------------------------------------------- #
# CSV / JSON loaders
# ---------------------------------------------------------------------- #
def load_csv(path: Path) -> List[Alert]:
    """Load alerts from a CSV file."""
    alerts: List[Alert] = []
    with open(path, "r", encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        headers = reader.fieldnames or []
        col_map = {c: _resolve_column(headers, c) for c in COLUMN_ALIASES}
        for i, row in enumerate(reader):
            alerts.append(_row_to_alert(row, col_map, fallback_id=f"csv-{i+1}"))
    logger.info("Loaded %d alerts from CSV %s", len(alerts), path)
    return alerts


def load_json(path: Path) -> List[Alert]:
    """Load alerts from a JSON file (array or ``{"alerts": [...]}``)."""
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, dict) and "alerts" in data:
        data = data["alerts"]
    if not isinstance(data, list):
        raise ValueError("JSON file must contain an array or {'alerts': [...]}.")
    alerts: List[Alert] = []
    for i, row in enumerate(data):
        if not isinstance(row, dict):
            continue
        # Use the dict keys directly as headers.
        headers = list(row.keys())
        col_map = {c: _resolve_column(headers, c) for c in COLUMN_ALIASES}
        alerts.append(_row_to_alert(row, col_map, fallback_id=f"json-{i+1}"))
    logger.info("Loaded %d alerts from JSON %s", len(alerts), path)
    return alerts


def _row_to_alert(row: Dict[str, Any],
                  col_map: Dict[str, Optional[str]],
                  fallback_id: str) -> Alert:
    """Convert a raw row dict to an :class:`Alert` instance."""
    def pick(canonical: str, default: str = "") -> str:
        col = col_map.get(canonical)
        if col and col in row and row[col] not in (None, ""):
            return str(row[col])
        return default

    timestamp = pick("timestamp")
    source_ip = pick("source_ip")
    destination_ip = pick("destination_ip")
    alert_name = pick("alert_name", default="(unknown alert)")
    severity = pick("severity", default="Medium").title() or "Medium"
    raw_log = pick("raw_log", default="")
    alert_id = pick("alert_id", default=fallback_id)

    # If no raw_log was provided, serialize the row itself.
    if not raw_log:
        raw_log = json.dumps(row, ensure_ascii=False, default=str)

    # Capture any extra columns for round-tripping.
    canonical_cols = {v for v in col_map.values() if v}
    extra = {k: v for k, v in row.items() if k not in canonical_cols}

    return Alert(
        timestamp=timestamp,
        source_ip=source_ip,
        destination_ip=destination_ip,
        alert_name=alert_name,
        severity=severity,
        raw_log=raw_log,
        alert_id=alert_id,
        extra=extra,
    )


# ---------------------------------------------------------------------- #
# Splunk loader
# ---------------------------------------------------------------------- #
def load_from_splunk(config: ConfigManager,
                     saved_search: Optional[str] = None,
                     max_results: int = 100) -> List[Alert]:
    """Poll a Splunk saved search and return the results as alerts.

    Uses the Splunk REST API (``services/search/saved/history`` and
    ``services/search/jobs``).  Authentication is via either a bearer
    token (recommended) or basic auth (username + password).

    Parameters
    ----------
    config:
        Application configuration; Splunk settings are read from the
        ``[splunk]`` and ``[endpoints]`` sections.
    saved_search:
        Optional name of the saved search to dispatch.  If omitted, the
        value from ``[splunk]/saved_search`` is used.
    max_results:
        Maximum number of results to return.
    """
    base_url = config.get_endpoint("splunk").rstrip("/")
    saved_search = saved_search or config.get("splunk", "saved_search", fallback="")
    verify_ssl = config.get_bool("splunk", "verify_ssl", fallback=True)
    bearer = config.get("splunk", "bearer_token", fallback="").strip()
    username = config.get("splunk", "username", fallback="").strip()
    password = config.get("splunk", "password", fallback="")

    if not saved_search:
        raise ValueError("No Splunk saved search configured.")

    headers = {"Accept": "application/json"}
    auth = None
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    elif username and password:
        auth = (username, password)
    else:
        raise ValueError("Splunk credentials not configured (need bearer_token or username+password).")

    # 1. Dispatch the saved search.
    dispatch_url = f"{base_url}/services/saved/searches/{requests.utils.quote(saved_search)}/dispatch"
    logger.info("Dispatching Splunk saved search '%s' ...", saved_search)
    resp = requests.post(
        dispatch_url,
        headers=headers,
        auth=auth,
        verify=verify_ssl,
        data={"output_mode": "json", "count": max_results},
        timeout=30,
    )
    resp.raise_for_status()
    sid = resp.json().get("sid")
    if not sid:
        raise RuntimeError(f"Splunk dispatch did not return a SID: {resp.text}")

    # 2. Poll for completion.
    results_url = f"{base_url}/services/search/jobs/{sid}/results"
    for _ in range(60):  # up to ~60 seconds
        time.sleep(1)
        r = requests.get(
            results_url,
            headers=headers,
            auth=auth,
            verify=verify_ssl,
            params={"output_mode": "json", "count": max_results},
            timeout=30,
        )
        if r.status_code == 200:
            break
        if r.status_code != 204:
            r.raise_for_status()
    else:
        raise TimeoutError(f"Splunk search {sid} did not complete in time.")

    payload = r.json()
    rows = payload.get("results", [])
    if not rows:
        logger.warning("Splunk saved search returned no results.")
        return []

    # Splunk returns rows where each cell is a list (multivalue field).
    # Flatten single-value lists.
    flat_rows: List[Dict[str, Any]] = []
    for row in rows:
        flat = {}
        for k, v in row.items():
            if isinstance(v, list) and len(v) == 1:
                flat[k] = v[0]
            else:
                flat[k] = v
        flat_rows.append(flat)

    headers_keys = list(flat_rows[0].keys())
    col_map = {c: _resolve_column(headers_keys, c) for c in COLUMN_ALIASES}
    alerts = [_row_to_alert(r, col_map, fallback_id=f"splunk-{i+1}")
              for i, r in enumerate(flat_rows)]
    logger.info("Loaded %d alerts from Splunk saved search '%s'.", len(alerts), saved_search)
    return alerts


# ---------------------------------------------------------------------- #
# Dispatch helper
# ---------------------------------------------------------------------- #
def load_alerts(source: str,
                config: Optional[ConfigManager] = None,
                path: Optional[Path] = None) -> List[Alert]:
    """Dispatch to the correct loader based on ``source``.

    Parameters
    ----------
    source:
        One of ``'csv'``, ``'json'``, ``'splunk'``.
    config:
        Required for ``source='splunk'``.
    path:
        Required for ``source in ('csv', 'json')``.
    """
    source = source.lower()
    if source == "csv":
        if not path:
            raise ValueError("path is required for CSV loading.")
        return load_csv(Path(path))
    if source == "json":
        if not path:
            raise ValueError("path is required for JSON loading.")
        return load_json(Path(path))
    if source == "splunk":
        if not config:
            raise ValueError("config is required for Splunk loading.")
        return load_from_splunk(config)
    raise ValueError(f"Unknown source: {source!r}")


__all__ = [
    "Alert",
    "load_csv",
    "load_json",
    "load_from_splunk",
    "load_alerts",
    "looks_like_ip",
]
