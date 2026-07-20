"""Right-side detail panel.

Shows the full information for the currently selected alert:
metadata, enrichment results, analyst notes (editable), and triage
action buttons.  Changes are pushed back to the parent via callbacks.
"""

from __future__ import annotations

from typing import Callable, Optional

import tkinter as tk
from tkinter import ttk, scrolledtext

from data.alert_loader import Alert
from gui.styles import COLORS
from utils.logger import get_logger

logger = get_logger(__name__)

# Statuses the analyst can apply to an alert.
TRIAGE_STATUSES = ["Unreviewed", "Escalated", "False Positive", "Resolved"]


class DetailPanel(ttk.Frame):
    """Right-side panel showing details + triage actions for one alert.

    Parameters
    ----------
    parent:
        Tkinter parent widget.
    on_status_change:
        Callback invoked with ``(alert, new_status)`` when the analyst
        picks a status from the dropdown.
    on_notes_change:
        Callback invoked with ``(alert, new_notes)`` when the analyst
        edits the notes field (debounced — see :meth:`_on_notes_key`).
    """

    def __init__(self,
                 parent: tk.Widget,
                 on_status_change: Optional[Callable[[Alert, str], None]] = None,
                 on_notes_change: Optional[Callable[[Alert, str], None]] = None,
                 **kwargs) -> None:
        super().__init__(parent, **kwargs)
        self.on_status_change = on_status_change
        self.on_notes_change = on_notes_change
        self._current: Optional[Alert] = None
        self._notes_debounce_id: Optional[str] = None

        self._build_widgets()

    # ------------------------------------------------------------------ #
    # Construction
    # ------------------------------------------------------------------ #
    def _build_widgets(self) -> None:
        # Outer container with consistent padding.
        container = ttk.Frame(self)
        container.pack(fill="both", expand=True, padx=8, pady=8)

        # Title.
        self.title_var = tk.StringVar(value="No alert selected")
        ttk.Label(container, textvariable=self.title_var,
                  style="Title.TLabel").pack(anchor="w", pady=(0, 8))

        # Metadata block (key/value pairs).
        meta_frame = ttk.LabelFrame(container, text="Alert Metadata",
                                    padding=8)
        meta_frame.pack(fill="x", pady=(0, 8))
        self.meta_vars: dict[str, tk.StringVar] = {}
        meta_fields = [
            ("alert_id", "Alert ID"),
            ("timestamp", "Timestamp"),
            ("severity", "Severity"),
            ("source_ip", "Source IP"),
            ("destination_ip", "Destination IP"),
            ("risk_score", "Risk Score"),
            ("risk_tier", "Risk Tier"),
            ("status", "Status"),
        ]
        for i, (key, label) in enumerate(meta_fields):
            ttk.Label(meta_frame, text=label,
                      style="Muted.TLabel").grid(row=i, column=0, sticky="w",
                                                 padx=(0, 8), pady=1)
            var = tk.StringVar(value="-")
            self.meta_vars[key] = var
            ttk.Label(meta_frame, textvariable=var).grid(
                row=i, column=1, sticky="w", pady=1)
        meta_frame.columnconfigure(1, weight=1)

        # Enrichment block.
        enr_frame = ttk.LabelFrame(container, text="Enrichment",
                                   padding=8)
        enr_frame.pack(fill="x", pady=(0, 8))
        self.enr_vars: dict[str, tk.StringVar] = {}
        enr_fields = [
            ("country", "Country"),
            ("isp", "ISP"),
            ("vt_malicious", "VT Malicious"),
            ("abuseipdb_confidence", "AbuseIPDB Conf."),
            ("abuseipdb_category", "Abuse Categories"),
            ("enriched", "Enriched?"),
            ("enrichment_errors", "Errors"),
        ]
        for i, (key, label) in enumerate(enr_fields):
            ttk.Label(enr_frame, text=label,
                      style="Muted.TLabel").grid(row=i, column=0, sticky="w",
                                                 padx=(0, 8), pady=1)
            var = tk.StringVar(value="-")
            self.enr_vars[key] = var
            ttk.Label(enr_frame, textvariable=var,
                      wraplength=320).grid(row=i, column=1, sticky="w", pady=1)
        enr_frame.columnconfigure(1, weight=1)

        # Triage actions.
        triage_frame = ttk.LabelFrame(container, text="Triage Actions",
                                      padding=8)
        triage_frame.pack(fill="x", pady=(0, 8))
        ttk.Label(triage_frame, text="Status:",
                  style="Muted.TLabel").grid(row=0, column=0, sticky="w",
                                             padx=(0, 8))
        self.status_var = tk.StringVar(value="Unreviewed")
        self.status_combo = ttk.Combobox(
            triage_frame, textvariable=self.status_var,
            values=TRIAGE_STATUSES, state="readonly", width=22)
        self.status_combo.grid(row=0, column=1, sticky="w")
        self.status_combo.bind("<<ComboboxSelected>>", self._on_status_change)

        # Quick-action buttons.
        btn_frame = ttk.Frame(triage_frame)
        btn_frame.grid(row=1, column=0, columnspan=2, sticky="w", pady=(8, 0))
        self.btn_escalate = ttk.Button(btn_frame, text="Escalate",
                                       width=11,
                                       command=lambda: self._set_status("Escalated"))
        self.btn_false_pos = ttk.Button(btn_frame, text="False Positive",
                                        width=13,
                                        command=lambda: self._set_status("False Positive"))
        self.btn_resolved = ttk.Button(btn_frame, text="Resolve",
                                       width=11,
                                       command=lambda: self._set_status("Resolved"))
        self.btn_escalate.grid(row=0, column=0, padx=(0, 4))
        self.btn_false_pos.grid(row=0, column=1, padx=4)
        self.btn_resolved.grid(row=0, column=2, padx=4)

        # Notes.
        notes_frame = ttk.LabelFrame(container, text="Analyst Notes",
                                     padding=8)
        notes_frame.pack(fill="both", expand=True, pady=(0, 8))
        self.notes_text = scrolledtext.ScrolledText(
            notes_frame, height=5, wrap="word",
            font=("Segoe UI", 10),
            background=COLORS["bg_table"],
            foreground=COLORS["fg"],
            insertbackground=COLORS["fg"],
            relief="flat", borderwidth=0,
        )
        self.notes_text.pack(fill="both", expand=True)
        self.notes_text.bind("<KeyRelease>", self._on_notes_key)

        # Raw log.
        log_frame = ttk.LabelFrame(container, text="Raw Log", padding=8)
        log_frame.pack(fill="both", expand=True, pady=(0, 8))
        self.log_text = scrolledtext.ScrolledText(
            log_frame, height=8, wrap="word",
            font=("Consolas", 9),
            background=COLORS["bg"],
            foreground=COLORS["fg_muted"],
            relief="flat", borderwidth=0,
        )
        self.log_text.pack(fill="both", expand=True)
        self.log_text.configure(state="disabled")

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def show_alert(self, alert: Optional[Alert]) -> None:
        """Render ``alert`` in the panel (or clear if ``None``)."""
        self._current = alert
        if alert is None:
            self.title_var.set("No alert selected")
            for v in list(self.meta_vars.values()) + list(self.enr_vars.values()):
                v.set("-")
            self.notes_text.delete("1.0", "end")
            self.log_text.configure(state="normal")
            self.log_text.delete("1.0", "end")
            self.log_text.configure(state="disabled")
            self.status_combo.configure(state="disabled")
            return

        self.title_var.set(alert.alert_name or "(unnamed alert)")
        self.meta_vars["alert_id"].set(alert.alert_id or "-")
        self.meta_vars["timestamp"].set(alert.timestamp or "-")
        self.meta_vars["severity"].set(alert.severity or "-")
        self.meta_vars["source_ip"].set(alert.source_ip or "-")
        self.meta_vars["destination_ip"].set(alert.destination_ip or "-")
        self.meta_vars["risk_score"].set(str(alert.risk_score))
        self.meta_vars["risk_tier"].set(alert.risk_tier)
        self.meta_vars["status"].set(alert.status)

        self.enr_vars["country"].set(alert.country or "-")
        self.enr_vars["isp"].set(alert.isp or "-")
        self.enr_vars["vt_malicious"].set(
            str(alert.vt_malicious) if alert.vt_malicious is not None else "-"
        )
        self.enr_vars["abuseipdb_confidence"].set(
            str(alert.abuseipdb_confidence) if alert.abuseipdb_confidence is not None else "-"
        )
        self.enr_vars["abuseipdb_category"].set(
            alert.abuseipdb_category or "-"
        )
        self.enr_vars["enriched"].set("Yes" if alert.enriched else "No")
        self.enr_vars["enrichment_errors"].set(
            "; ".join(alert.enrichment_errors) or "None"
        )

        # Notes — block the KeyRelease handler while we update.
        self.notes_text.delete("1.0", "end")
        if alert.notes:
            self.notes_text.insert("1.0", alert.notes)

        # Raw log.
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.insert("1.0", alert.raw_log or "")
        self.log_text.configure(state="disabled")

        # Status combo.
        self.status_var.set(alert.status)
        self.status_combo.configure(state="readonly")

    # ------------------------------------------------------------------ #
    # Internal handlers
    # ------------------------------------------------------------------ #
    def _set_status(self, status: str) -> None:
        """Update the combobox and fire the change callback."""
        if self._current is None:
            return
        self.status_var.set(status)
        if self.on_status_change:
            self.on_status_change(self._current, status)

    def _on_status_change(self, _event: tk.Event) -> None:
        if self._current is None:
            return
        if self.on_status_change:
            self.on_status_change(self._current, self.status_var.get())

    def _on_notes_key(self, _event: tk.Event) -> None:
        """Debounce notes updates (fire 500ms after the last keystroke)."""
        if self._current is None or self.on_notes_change is None:
            return
        if self._notes_debounce_id is not None:
            self.after_cancel(self._notes_debounce_id)
        self._notes_debounce_id = self.after(500, self._fire_notes_change)

    def _fire_notes_change(self) -> None:
        self._notes_debounce_id = None
        if self._current is None or self.on_notes_change is None:
            return
        new_notes = self.notes_text.get("1.0", "end").rstrip("\n")
        self.on_notes_change(self._current, new_notes)


__all__ = ["DetailPanel", "TRIAGE_STATUSES"]
