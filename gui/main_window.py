"""Main application window for the SOC Triage Tool.

This module wires together the alert table, the detail panel, the
filter controls, the toolbar, the status bar, and the background
enrichment pipeline.  All long-running operations (enrichment, report
generation) run on background threads so the GUI stays responsive.
"""

from __future__ import annotations

import csv
import json
import queue
import threading
from pathlib import Path
from typing import Dict, List, Optional

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

import requests

from data.alert_loader import Alert, load_alerts
from data.database import EnrichmentCache
from enrichment.base import EnrichmentError
from enrichment.ip_geolocation import IPGeolocationEnricher
from enrichment.virustotal import VirusTotalEnricher
from enrichment.abuseipdb import AbuseIPDBEnricher
from gui.alert_table import AlertTable
from gui.detail_panel import DetailPanel, TRIAGE_STATUSES
from gui.settings_dialog import SettingsDialog
from gui.styles import COLORS, tier_color, apply_theme
from reporting import report_generator
from utils.config import ConfigManager, DEFAULT_CONFIG_PATH
from utils.logger import get_logger
from utils.risk_scorer import RiskScorer

logger = get_logger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_CSV = PROJECT_ROOT / "samples" / "sample_alerts.csv"


class MainWindow:
    """Top-level controller for the SOC Triage Tool GUI.

    The window is built lazily — calling :meth:`run` enters the Tk main
    loop.  All background work is dispatched via Python ``threading``
    and the results are funneled back to the GUI thread through a
    thread-safe :class:`queue.Queue`.
    """

    def __init__(self, config_path: Optional[Path] = None) -> None:
        self.config = ConfigManager(config_path or DEFAULT_CONFIG_PATH)
        self.cache = EnrichmentCache(self.config)
        self.scorer = RiskScorer(self.config)
        self.alerts: List[Alert] = []

        # Background-thread infrastructure.
        self._ui_queue: queue.Queue = queue.Queue()
        self._enrich_workers: List[threading.Thread] = []
        self._enrich_cancel = threading.Event()
        self._enrich_total = 0
        self._enrich_done = 0

        # Tkinter root — created in build() so __init__ stays cheap.
        self.root: Optional[tk.Tk] = None
        self.table: Optional[AlertTable] = None
        self.detail: Optional[DetailPanel] = None
        self.status_var = tk.StringVar(value="Ready")
        self.count_var = tk.StringVar(value="0 alerts")
        self.progress_var = tk.DoubleVar(value=0.0)

    # ------------------------------------------------------------------ #
    # Build the UI
    # ------------------------------------------------------------------ #
    def build(self) -> "MainWindow":
        """Construct the main window and all child widgets."""
        try:
            import ttkbootstrap as ttkb
            self.root = ttkb.Window(title="SOC Alert Triage & Enrichment Tool",
                                    themename="cyborg",
                                    minsize=(1280, 720))
        except ImportError:
            self.root = tk.Tk()
            self.root.title("SOC Alert Triage & Enrichment Tool")
            self.root.minsize(1280, 720)
            apply_theme()

        # Restore window size from config.
        w = self.config.get_int("ui", "window_width", fallback=1400)
        h = self.config.get_int("ui", "window_height", fallback=850)
        try:
            self.root.geometry(f"{w}x{h}")
        except tk.TclError:
            pass

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        self._build_toolbar()
        self._build_body()
        self._build_statusbar()

        # Start polling the UI queue.
        self.root.after(100, self._drain_ui_queue)

        # Auto-load the sample CSV so the tool is immediately useful.
        if SAMPLE_CSV.exists():
            try:
                self._load_from_path(SAMPLE_CSV, source="csv")
            except Exception as exc:
                logger.warning("Could not auto-load sample CSV: %s", exc)

        return self

    # ------------------------------------------------------------------ #
    # Toolbar
    # ------------------------------------------------------------------ #
    def _build_toolbar(self) -> None:
        bar = ttk.Frame(self.root, padding=(8, 6))
        bar.pack(side="top", fill="x")

        ttk.Button(bar, text="Load CSV",
                   command=self._on_load_csv).pack(side="left", padx=(0, 4))
        ttk.Button(bar, text="Load JSON",
                   command=self._on_load_json).pack(side="left", padx=4)
        ttk.Button(bar, text="Load from Splunk",
                   command=self._on_load_splunk).pack(side="left", padx=4)
        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y",
                                                    padx=8, pady=2)
        ttk.Button(bar, text="Enrich Selected",
                   command=self._on_enrich_selected).pack(side="left",
                                                          padx=(0, 4))
        ttk.Button(bar, text="Batch Enrich All",
                   command=self._on_enrich_all).pack(side="left", padx=4)
        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y",
                                                    padx=8, pady=2)
        ttk.Button(bar, text="Export CSV",
                   command=self._on_export_csv).pack(side="left", padx=4)
        ttk.Button(bar, text="Export JSON",
                   command=self._on_export_json).pack(side="left", padx=4)
        ttk.Button(bar, text="PDF Report",
                   command=self._on_pdf_report).pack(side="left", padx=4)
        ttk.Button(bar, text="HTML Report",
                   command=self._on_html_report).pack(side="left", padx=4)
        ttk.Button(bar, text="Create Ticket (stub)",
                   command=self._on_create_ticket).pack(side="left", padx=4)

        # Right-aligned buttons.
        ttk.Button(bar, text="Settings",
                   command=self._on_settings).pack(side="right", padx=4)
        ttk.Button(bar, text="Clear Cache",
                   command=self._on_clear_cache).pack(side="right", padx=4)

    # ------------------------------------------------------------------ #
    # Body (filters + table + detail)
    # ------------------------------------------------------------------ #
    def _build_body(self) -> None:
        body = ttk.Frame(self.root)
        body.pack(side="top", fill="both", expand=True, padx=8, pady=4)

        # Left filter panel.
        self._build_filters(body)

        # Center table.
        self.table = AlertTable(body, on_select=self._on_alert_selected)
        self.table.pack(side="left", fill="both", expand=True, padx=(8, 4))

        # Right detail panel.
        self.detail = DetailPanel(
            body,
            on_status_change=self._on_status_change,
            on_notes_change=self._on_notes_change,
        )
        self.detail.pack(side="right", fill="y", padx=(4, 0))

    def _build_filters(self, parent: tk.Widget) -> None:
        panel = ttk.LabelFrame(parent, text="Filters", padding=10,
                               width=240)
        panel.pack(side="left", fill="y", padx=(0, 8))
        panel.pack_propagate(False)  # keep fixed width

        # Status filter
        ttk.Label(panel, text="Status", style="Muted.TLabel").pack(anchor="w",
                                                                   pady=(4, 0))
        self.filter_status_var = tk.StringVar(value="All")
        ttk.Combobox(panel, textvariable=self.filter_status_var,
                     values=["All"] + TRIAGE_STATUSES,
                     state="readonly", width=22).pack(fill="x", pady=(0, 8))

        # Severity filter
        ttk.Label(panel, text="Severity",
                  style="Muted.TLabel").pack(anchor="w", pady=(4, 0))
        self.filter_severity_var = tk.StringVar(value="All")
        ttk.Combobox(panel, textvariable=self.filter_severity_var,
                     values=["All", "Critical", "High", "Medium", "Low",
                             "Informational"],
                     state="readonly", width=22).pack(fill="x", pady=(0, 8))

        # Min risk score
        ttk.Label(panel, text="Min Risk Score",
                  style="Muted.TLabel").pack(anchor="w", pady=(4, 0))
        self.filter_risk_var = tk.IntVar(value=0)
        scale = ttk.Scale(panel, from_=0, to=100,
                          variable=self.filter_risk_var,
                          command=lambda _e: self._apply_filters())
        scale.pack(fill="x", pady=(0, 2))
        self.filter_risk_label = ttk.Label(panel, text="0",
                                           style="Muted.TLabel")
        self.filter_risk_label.pack(anchor="w", pady=(0, 8))

        # Country filter (text)
        ttk.Label(panel, text="Country (contains)",
                  style="Muted.TLabel").pack(anchor="w", pady=(4, 0))
        self.filter_country_var = tk.StringVar()
        ttk.Entry(panel, textvariable=self.filter_country_var,
                  width=22).pack(fill="x", pady=(0, 8))

        # Source IP filter (text)
        ttk.Label(panel, text="Source IP (contains)",
                  style="Muted.TLabel").pack(anchor="w", pady=(4, 0))
        self.filter_ip_var = tk.StringVar()
        ttk.Entry(panel, textvariable=self.filter_ip_var,
                  width=22).pack(fill="x", pady=(0, 12))

        ttk.Separator(panel, orient="horizontal").pack(fill="x", pady=4)
        ttk.Button(panel, text="Apply Filters",
                   command=self._apply_filters).pack(fill="x", pady=(0, 4))
        ttk.Button(panel, text="Reset Filters",
                   command=self._reset_filters).pack(fill="x")

        # Bind key release on the text filters to auto-apply.
        self.filter_country_var.trace_add("write",
                                          lambda *_: self._apply_filters())
        self.filter_ip_var.trace_add("write",
                                     lambda *_: self._apply_filters())
        self.filter_status_var.trace_add("write",
                                         lambda *_: self._apply_filters())
        self.filter_severity_var.trace_add("write",
                                           lambda *_: self._apply_filters())

        # Cache stats at the bottom of the panel.
        ttk.Separator(panel, orient="horizontal").pack(fill="x", pady=8)
        ttk.Label(panel, text="Cache Stats",
                  style="Muted.TLabel").pack(anchor="w")
        self.cache_stats_var = tk.StringVar(value="0 entries")
        ttk.Label(panel, textvariable=self.cache_stats_var).pack(anchor="w")
        self._refresh_cache_stats()

    # ------------------------------------------------------------------ #
    # Status bar
    # ------------------------------------------------------------------ #
    def _build_statusbar(self) -> None:
        bar = ttk.Frame(self.root, padding=(8, 4))
        bar.pack(side="bottom", fill="x")

        ttk.Label(bar, textvariable=self.count_var,
                  style="Muted.TLabel").pack(side="left")
        self.progress = ttk.Progressbar(bar, variable=self.progress_var,
                                        maximum=100, length=200)
        self.progress.pack(side="left", padx=12)
        ttk.Label(bar, textvariable=self.status_var,
                  style="Muted.TLabel").pack(side="right")

    # ------------------------------------------------------------------ #
    # Loading
    # ------------------------------------------------------------------ #
    def _on_load_csv(self) -> None:
        path = filedialog.askopenfilename(
            title="Open alerts CSV",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialdir=str(PROJECT_ROOT / "samples"),
        )
        if not path:
            return
        try:
            self._load_from_path(Path(path), source="csv")
        except Exception as exc:
            self._show_error(f"Failed to load CSV: {exc}")

    def _on_load_json(self) -> None:
        path = filedialog.askopenfilename(
            title="Open alerts JSON",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            self._load_from_path(Path(path), source="json")
        except Exception as exc:
            self._show_error(f"Failed to load JSON: {exc}")

    def _on_load_splunk(self) -> None:
        if not self.config.get("splunk", "saved_search", fallback=""):
            self._show_error(
                "Splunk not configured. Open Settings → Splunk to configure.")
            return
        if not messagebox.askyesno(
                "Splunk",
                "Poll the configured Splunk saved search now?"):
            return
        self.status_var.set("Polling Splunk...")
        threading.Thread(target=self._splunk_loader_thread,
                         daemon=True).start()

    def _splunk_loader_thread(self) -> None:
        try:
            alerts = load_alerts("splunk", config=self.config)
            self._ui_queue.put(("splunk_loaded", alerts))
        except Exception as exc:
            logger.exception("Splunk load failed.")
            self._ui_queue.put(("error", f"Splunk load failed: {exc}"))

    def _load_from_path(self, path: Path, source: str = "csv") -> None:
        alerts = load_alerts(source, path=path)
        self.alerts = alerts
        # Recompute risk scores (in case config changed since last load).
        for a in self.alerts:
            self._recompute_risk(a)
        self.table.set_alerts(self.alerts)
        self._update_counts()
        self.status_var.set(f"Loaded {len(self.alerts)} alerts from {path.name}")
        logger.info("Loaded %d alerts from %s", len(self.alerts), path)

    # ------------------------------------------------------------------ #
    # Enrichment
    # ------------------------------------------------------------------ #
    def _on_enrich_selected(self) -> None:
        alert = self.table.get_selected_alert()
        if alert is None:
            self._show_info("Select an alert first.")
            return
        self.status_var.set(f"Enriching alert {alert.alert_id}...")
        threading.Thread(target=self._enrich_one_thread,
                         args=(alert.alert_id,),
                         daemon=True).start()

    def _on_enrich_all(self) -> None:
        # Enrich all *visible* alerts.
        visible = self.table.get_visible_alerts()
        to_enrich = [a for a in visible
                     if a.source_ip and not a.enriched]
        if not to_enrich:
            self._show_info("No visible alerts need enrichment.")
            return
        if any(not a.source_ip for a in to_enrich):
            pass  # already filtered out
        self._enrich_cancel.clear()
        self._enrich_total = len(to_enrich)
        self._enrich_done = 0
        self.progress_var.set(0.0)
        self.status_var.set(f"Batch enriching {len(to_enrich)} alerts...")
        # Spawn a single coordinator thread that fans out to a small pool.
        threading.Thread(target=self._enrich_batch_thread,
                         args=(to_enrich,),
                         daemon=True).start()

    def _enrich_batch_thread(self, alerts: List[Alert]) -> None:
        """Enrich a list of alerts concurrently (max 3 workers)."""
        sem = threading.Semaphore(3)  # limit concurrency for rate limits
        results: Dict[str, Alert] = {}
        results_lock = threading.Lock()

        def worker(alert: Alert) -> None:
            with sem:
                if self._enrich_cancel.is_set():
                    return
                try:
                    enriched = self._enrich_alert(alert)
                    with results_lock:
                        results[alert.alert_id] = enriched
                    self._ui_queue.put(("alert_enriched", enriched))
                except Exception as exc:
                    logger.exception("Enrichment failed for %s", alert.alert_id)
                    alert.enrichment_errors.append(str(exc))
                    self._ui_queue.put(("alert_enriched", alert))
                finally:
                    self._ui_queue.put(("enrich_progress", None))

        threads = [threading.Thread(target=worker, args=(a,),
                                    name=f"enrich-{a.alert_id}",
                                    daemon=True)
                   for a in alerts]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self._ui_queue.put(("enrich_complete", None))

    def _enrich_one_thread(self, alert_id: str) -> None:
        """Enrich a single alert by ID."""
        alert = next((a for a in self.alerts if a.alert_id == alert_id), None)
        if alert is None:
            self._ui_queue.put(("error", f"Alert {alert_id} not found."))
            return
        try:
            enriched = self._enrich_alert(alert)
            self._ui_queue.put(("alert_enriched", enriched))
        except Exception as exc:
            logger.exception("Enrichment failed for %s", alert_id)
            alert.enrichment_errors.append(str(exc))
            self._ui_queue.put(("alert_enriched", alert))
        finally:
            self._ui_queue.put(("enrich_complete", None))

    def _enrich_alert(self, alert: Alert) -> Alert:
        """Run all enrichers for the alert's source IP and update it.

        Runs synchronously in the calling thread (a worker thread).
        """
        if not alert.source_ip:
            alert.enriched = False
            alert.enrichment_errors.append("No source IP to enrich.")
            return alert

        session = requests.Session()
        enrichers = []
        # Always include geolocation (no key needed).
        enrichers.append(IPGeolocationEnricher(self.config, self.cache, session))
        # Only include paid enrichers if a key is configured.
        if self.config.get_api_key("virustotal"):
            enrichers.append(VirusTotalEnricher(self.config, self.cache, session))
        if self.config.get_api_key("abuseipdb"):
            enrichers.append(AbuseIPDBEnricher(self.config, self.cache, session))

        for enricher in enrichers:
            try:
                payload = enricher.enrich(alert.source_ip)
                self._merge_enrichment(alert, enricher.name, payload)
            except EnrichmentError as exc:
                logger.warning("%s failed for %s: %s",
                               enricher.name, alert.source_ip, exc)
                alert.enrichment_errors.append(f"{enricher.name}: {exc}")

        alert.enriched = True
        self._recompute_risk(alert)
        return alert

    def _merge_enrichment(self, alert: Alert, enricher: str,
                          payload: Dict) -> None:
        """Copy fields from the enricher payload onto the alert."""
        if enricher == "ip_geolocation":
            alert.country = payload.get("country", "") or alert.country
            alert.isp = payload.get("isp", "") or alert.isp
        elif enricher == "virustotal":
            mal = payload.get("malicious")
            if mal is not None:
                alert.vt_malicious = int(mal)
        elif enricher == "abuseipdb":
            conf = payload.get("abuse_confidence_score")
            if conf is not None:
                alert.abuseipdb_confidence = int(conf)
            alert.abuseipdb_category = payload.get("categories", "") or alert.abuseipdb_category

    def _recompute_risk(self, alert: Alert) -> None:
        """Recompute the composite risk score and tier for ``alert``."""
        score = self.scorer.score(
            severity=alert.severity,
            vt_malicious=alert.vt_malicious,
            abuseipdb_confidence=alert.abuseipdb_confidence,
            country=alert.country,
        )
        alert.risk_score = score
        alert.risk_tier = self.scorer.tier(score)

    # ------------------------------------------------------------------ #
    # Filters
    # ------------------------------------------------------------------ #
    def _apply_filters(self) -> None:
        if self.table is None:
            return
        status = self.filter_status_var.get()
        severity = self.filter_severity_var.get()
        min_risk = int(self.filter_risk_var.get())
        country = self.filter_country_var.get().strip().lower()
        ip = self.filter_ip_var.get().strip().lower()

        self.filter_risk_label.configure(text=str(min_risk))

        def matches(a: Alert) -> bool:
            if status != "All" and a.status != status:
                return False
            if severity != "All" and a.severity.lower() != severity.lower():
                return False
            if a.risk_score < min_risk:
                return False
            if country and country not in (a.country or "").lower():
                return False
            if ip and ip not in (a.source_ip or "").lower():
                return False
            return True

        filtered = [a for a in self.alerts if matches(a)]
        self.table.set_alerts(filtered)
        self.count_var.set(f"{len(filtered)} / {len(self.alerts)} alerts")

    def _reset_filters(self) -> None:
        self.filter_status_var.set("All")
        self.filter_severity_var.set("All")
        self.filter_risk_var.set(0)
        self.filter_country_var.set("")
        self.filter_ip_var.set("")
        self._apply_filters()

    # ------------------------------------------------------------------ #
    # Selection / triage actions
    # ------------------------------------------------------------------ #
    def _on_alert_selected(self, alert: Optional[Alert]) -> None:
        self.detail.show_alert(alert)

    def _on_status_change(self, alert: Alert, new_status: str) -> None:
        # Update the canonical alert object.
        for i, a in enumerate(self.alerts):
            if a.alert_id == alert.alert_id:
                self.alerts[i].status = new_status
                alert = self.alerts[i]
                break
        self.table.update_alert(alert)
        self.detail.show_alert(alert)
        logger.info("Alert %s status -> %s", alert.alert_id, new_status)

    def _on_notes_change(self, alert: Alert, new_notes: str) -> None:
        for i, a in enumerate(self.alerts):
            if a.alert_id == alert.alert_id:
                self.alerts[i].notes = new_notes
                break
        logger.info("Alert %s notes updated (%d chars).",
                    alert.alert_id, len(new_notes))

    # ------------------------------------------------------------------ #
    # Export / reporting
    # ------------------------------------------------------------------ #
    def _on_export_csv(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Export to CSV",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
            initialdir=str(PROJECT_ROOT / "reports"),
            initialfile="enriched_alerts.csv",
        )
        if not path:
            return
        try:
            self._write_csv(self.alerts, Path(path))
            self._show_info(f"Exported {len(self.alerts)} alerts to:\n{path}")
        except Exception as exc:
            self._show_error(f"CSV export failed: {exc}")

    def _on_export_json(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Export to JSON",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")],
            initialdir=str(PROJECT_ROOT / "reports"),
            initialfile="enriched_alerts.json",
        )
        if not path:
            return
        try:
            data = [a.to_dict() for a in self.alerts]
            Path(path).write_text(
                json.dumps({"alerts": data}, indent=2, ensure_ascii=False,
                           default=str),
                encoding="utf-8",
            )
            self._show_info(f"Exported {len(self.alerts)} alerts to:\n{path}")
        except Exception as exc:
            self._show_error(f"JSON export failed: {exc}")

    def _on_pdf_report(self) -> None:
        alerts = self.table.get_visible_alerts() or self.alerts
        if not alerts:
            self._show_info("No alerts to include in the report.")
            return
        path = filedialog.asksaveasfilename(
            title="Save PDF report",
            defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf")],
            initialdir=str(PROJECT_ROOT / "reports"),
            initialfile="triage_report.pdf",
        )
        if not path:
            return
        self.status_var.set("Generating PDF...")
        threading.Thread(target=self._pdf_thread,
                         args=(alerts, Path(path)),
                         daemon=True).start()

    def _pdf_thread(self, alerts: List[Alert], path: Path) -> None:
        try:
            report_generator.generate_pdf(alerts, output_path=path)
            self._ui_queue.put(("info", f"PDF report written to:\n{path}"))
        except Exception as exc:
            logger.exception("PDF generation failed.")
            self._ui_queue.put(("error", f"PDF generation failed: {exc}"))
        finally:
            self._ui_queue.put(("status", "Ready"))

    def _on_html_report(self) -> None:
        alerts = self.table.get_visible_alerts() or self.alerts
        if not alerts:
            self._show_info("No alerts to include in the report.")
            return
        path = filedialog.asksaveasfilename(
            title="Save HTML report",
            defaultextension=".html",
            filetypes=[("HTML files", "*.html")],
            initialdir=str(PROJECT_ROOT / "reports"),
            initialfile="triage_report.html",
        )
        if not path:
            return
        try:
            report_generator.generate_html(alerts, output_path=Path(path))
            self._show_info(f"HTML report written to:\n{path}")
        except Exception as exc:
            self._show_error(f"HTML generation failed: {exc}")

    def _on_create_ticket(self) -> None:
        alert = self.table.get_selected_alert()
        if alert is None:
            self._show_info("Select an alert first.")
            return
        ticket_id = report_generator.create_ticket_stub(alert, system="thehive")
        alert.notes = (alert.notes + "\n" if alert.notes else "") + \
            f"[Ticket {ticket_id} created]"
        self.table.update_alert(alert)
        self.detail.show_alert(alert)
        self._show_info(
            f"Stub ticket created.\nTicket ID: {ticket_id}\n"
            "(Replace create_ticket_stub in reporting/report_generator.py "
            "with a real API call to integrate with TheHive / ServiceNow.)"
        )

    def _write_csv(self, alerts: List[Alert], path: Path) -> None:
        if not alerts:
            path.write_text("", encoding="utf-8")
            return
        # Build column list from the first alert's dict (extra fields included).
        first = alerts[0].to_dict()
        cols = list(first.keys())
        with open(path, "w", encoding="utf-8-sig", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
            writer.writeheader()
            for a in alerts:
                writer.writerow(a.to_dict())

    # ------------------------------------------------------------------ #
    # Settings / cache
    # ------------------------------------------------------------------ #
    def _on_settings(self) -> None:
        dlg = SettingsDialog(self.root, self.config)
        # Wire up the cache-clear callback.
        dlg._clear_cache_callback = self.cache.clear
        # Re-init the scorer after save (config may have changed).
        self.root.wait_window(dlg)
        self.scorer = RiskScorer(self.config)
        # Recompute scores for all alerts.
        for a in self.alerts:
            self._recompute_risk(a)
        self.table.set_alerts(self.alerts)
        self._refresh_cache_stats()

    def _on_clear_cache(self) -> None:
        if not messagebox.askyesno(
                "Confirm", "Clear all cached enrichment results?"):
            return
        deleted = self.cache.clear()
        self._refresh_cache_stats()
        self._show_info(f"Cleared {deleted} cache entries.")

    def _refresh_cache_stats(self) -> None:
        stats = self.cache.stats()
        self.cache_stats_var.set(
            f"{stats['entries']} entries / {stats['distinct_ips']} IPs"
        )

    # ------------------------------------------------------------------ #
    # UI queue drain
    # ------------------------------------------------------------------ #
    def _drain_ui_queue(self) -> None:
        try:
            while True:
                kind, payload = self._ui_queue.get_nowait()
                self._handle_ui_event(kind, payload)
        except queue.Empty:
            pass
        finally:
            if self.root is not None:
                self.root.after(100, self._drain_ui_queue)

    def _handle_ui_event(self, kind: str, payload) -> None:
        if kind == "alert_enriched":
            alert: Alert = payload
            # Update the canonical list and the table.
            for i, a in enumerate(self.alerts):
                if a.alert_id == alert.alert_id:
                    self.alerts[i] = alert
                    break
            self.table.update_alert(alert)
            # If the user is currently viewing this alert, refresh detail.
            current = self.table.get_selected_alert()
            if current and current.alert_id == alert.alert_id:
                self.detail.show_alert(alert)
            self._refresh_cache_stats()
        elif kind == "enrich_progress":
            self._enrich_done += 1
            if self._enrich_total > 0:
                pct = (self._enrich_done / self._enrich_total) * 100
                self.progress_var.set(pct)
                self.status_var.set(
                    f"Enriching... {self._enrich_done}/{self._enrich_total}")
        elif kind == "enrich_complete":
            self.progress_var.set(0.0)
            self.status_var.set(
                f"Enrichment complete. {self._enrich_done} alerts processed.")
            self._update_counts()
            self._refresh_cache_stats()
        elif kind == "splunk_loaded":
            self.alerts = payload
            for a in self.alerts:
                self._recompute_risk(a)
            self.table.set_alerts(self.alerts)
            self._update_counts()
            self.status_var.set(
                f"Loaded {len(self.alerts)} alerts from Splunk.")
        elif kind == "info":
            self._show_info(payload)
        elif kind == "error":
            self._show_error(payload)
        elif kind == "status":
            self.status_var.set(payload)

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _update_counts(self) -> None:
        total = len(self.alerts)
        critical = sum(1 for a in self.alerts if a.risk_tier == "Critical")
        high = sum(1 for a in self.alerts if a.risk_tier == "High")
        unreviewed = sum(1 for a in self.alerts if a.status == "Unreviewed")
        self.count_var.set(
            f"{total} alerts | {critical} Critical | {high} High | "
            f"{unreviewed} Unreviewed"
        )

    def _show_info(self, msg: str) -> None:
        if self.root:
            messagebox.showinfo("SOC Triage Tool", msg, parent=self.root)

    def _show_error(self, msg: str) -> None:
        logger.error(msg)
        if self.root:
            messagebox.showerror("SOC Triage Tool", msg, parent=self.root)

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #
    def _on_close(self) -> None:
        self._enrich_cancel.set()
        # Save window size.
        try:
            if self.root is not None:
                w = self.root.winfo_width()
                h = self.root.winfo_height()
                if w > 100 and h > 100:
                    self.config.set("ui", "window_width", w)
                    self.config.set("ui", "window_height", h)
                    self.config.save()
        except Exception:
            pass
        try:
            self.cache.close()
        except Exception:
            pass
        if self.root is not None:
            self.root.destroy()

    def run(self) -> None:
        if self.root is None:
            self.build()
        assert self.root is not None
        self.root.mainloop()


__all__ = ["MainWindow"]
