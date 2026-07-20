"""Treeview-based alert table widget.

Displays alerts in a sortable, color-coded table.  The columns shown
are a fixed superset of the canonical alert fields; risk tier is
indicated both by an explicit column and by row tag-based coloring.

The widget is purely presentational — it owns no state and notifies the
parent of selection changes via a callback.
"""

from __future__ import annotations

from typing import Callable, List, Optional

import tkinter as tk
from tkinter import ttk

from data.alert_loader import Alert
from gui.styles import COLORS, tier_color
from utils.logger import get_logger

logger = get_logger(__name__)


# (column_id, header text, width in px, anchor)
COLUMNS = [
    ("timestamp",      "Timestamp",    140, "w"),
    ("alert_name",     "Alert Name",   240, "w"),
    ("severity",       "Severity",     80,  "center"),
    ("source_ip",      "Source IP",    120, "w"),
    ("destination_ip", "Dest IP",      120, "w"),
    ("country",        "Country",      100, "w"),
    ("isp",            "ISP",          160, "w"),
    ("vt_malicious",   "VT Mal.",      60,  "center"),
    ("abuseipdb_conf", "Abuse Conf.",  80,  "center"),
    ("risk_score",     "Risk",         50,  "center"),
    ("risk_tier",      "Tier",         80,  "center"),
    ("status",         "Status",       110, "center"),
]


class AlertTable(ttk.Frame):
    """Sortable, color-coded table of alerts.

    Parameters
    ----------
    parent:
        Tkinter parent widget.
    on_select:
        Callback invoked with the selected :class:`Alert` (or ``None``)
        whenever the selection changes.
    """

    def __init__(self,
                 parent: tk.Widget,
                 on_select: Optional[Callable[[Optional[Alert]], None]] = None,
                 **kwargs) -> None:
        super().__init__(parent, **kwargs)
        self.on_select = on_select
        self._alerts: List[Alert] = []
        self._sort_col: str = "risk_score"
        self._sort_reverse: bool = True

        self._build_widgets()
        self._apply_tags()

    # ------------------------------------------------------------------ #
    # Widget construction
    # ------------------------------------------------------------------ #
    def _build_widgets(self) -> None:
        # Toolbar with sort hint and column picker (kept simple).
        toolbar = ttk.Frame(self)
        toolbar.pack(fill="x", padx=4, pady=(4, 2))
        ttk.Label(toolbar,
                  text="Alerts (click a column header to sort)",
                  style="Muted.TLabel").pack(side="left")

        # Treeview inside a scrollable container.
        tree_container = ttk.Frame(self)
        tree_container.pack(fill="both", expand=True, padx=4, pady=4)

        col_ids = [c[0] for c in COLUMNS]
        self.tree = ttk.Treeview(
            tree_container,
            columns=col_ids,
            show="headings",
            selectmode="browse",
        )
        for cid, title, width, anchor in COLUMNS:
            self.tree.heading(cid, text=title,
                              command=lambda c=cid: self.sort_by(c))
            self.tree.column(cid, width=width, anchor=anchor,
                             stretch=(cid == "alert_name"))

        vsb = ttk.Scrollbar(tree_container, orient="vertical",
                            command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_container, orient="horizontal",
                            command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tree_container.rowconfigure(0, weight=1)
        tree_container.columnconfigure(0, weight=1)

        self.tree.bind("<<TreeviewSelect>>", self._handle_select)

    def _apply_tags(self) -> None:
        """Configure row-background tags for each risk tier."""
        for tier, key in [("Critical", "critical"),
                          ("High",     "high"),
                          ("Medium",   "medium"),
                          ("Low",      "low")]:
            self.tree.tag_configure(tier, background=COLORS[key],
                                    foreground="#FFFFFF")
        # Make sure the selected row remains readable.
        self.tree.tag_configure("selected", foreground="#FFFFFF")

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def set_alerts(self, alerts: List[Alert]) -> None:
        """Replace the table contents with ``alerts``."""
        self._alerts = list(alerts)
        self._render()

    def update_alert(self, alert: Alert) -> None:
        """Refresh a single alert row in place (matched by alert_id)."""
        for i, a in enumerate(self._alerts):
            if a.alert_id == alert.alert_id:
                self._alerts[i] = alert
                break
        # Re-render to keep ordering / colors in sync.
        self._render()

    def get_visible_alerts(self) -> List[Alert]:
        """Return the alerts currently shown (after sorting)."""
        return list(self._alerts)

    def get_selected_alert(self) -> Optional[Alert]:
        """Return the currently selected :class:`Alert`, or ``None``."""
        sel = self.tree.selection()
        if not sel:
            return None
        try:
            idx = int(self.tree.item(sel[0], "tags")[0]
                      if self.tree.item(sel[0], "tags") else -1)
        except (ValueError, IndexError):
            return None
        # The first tag stores the index into the *sorted* list.
        sorted_alerts = self._sorted_alerts()
        if 0 <= idx < len(sorted_alerts):
            return sorted_alerts[idx]
        return None

    # ------------------------------------------------------------------ #
    # Sorting
    # ------------------------------------------------------------------ #
    def sort_by(self, col: str) -> None:
        """Sort the table by column ``col``; toggle direction if re-clicked."""
        if col == self._sort_col:
            self._sort_reverse = not self._sort_reverse
        else:
            self._sort_col = col
            self._sort_reverse = False
        self._render()

    def _sorted_alerts(self) -> List[Alert]:
        """Return ``self._alerts`` sorted by the current sort column."""
        col = self._sort_col
        reverse = self._sort_reverse

        def key(a: Alert):
            v = getattr(a, col, None)
            if v is None or v == "":
                # Push empty values to the bottom regardless of direction.
                return (0, "") if not reverse else (0, "")
            if col in ("risk_score", "vt_malicious", "abuseipdb_conf"):
                try:
                    return (1, float(v))
                except (TypeError, ValueError):
                    return (0, 0.0)
            return (1, str(v).lower())

        return sorted(self._alerts, key=key, reverse=reverse)

    # ------------------------------------------------------------------ #
    # Rendering
    # ------------------------------------------------------------------ #
    def _render(self) -> None:
        self.tree.delete(*self.tree.get_children())
        for i, a in enumerate(self._sorted_alerts()):
            values = (
                a.timestamp,
                a.alert_name,
                a.severity,
                a.source_ip,
                a.destination_ip,
                a.country,
                a.isp,
                str(a.vt_malicious) if a.vt_malicious is not None else "-",
                str(a.abuseipdb_confidence) if a.abuseipdb_confidence is not None else "-",
                a.risk_score,
                a.risk_tier,
                a.status,
            )
            # First tag is the row index (used by get_selected_alert);
            # second tag is the tier (for row coloring).
            self.tree.insert("", "end",
                             iid=str(i),
                             values=values,
                             tags=(str(i), a.risk_tier))
        # Trigger selection callback if nothing is selected.
        if not self.tree.selection() and self.on_select:
            self.on_select(None)

    # ------------------------------------------------------------------ #
    # Events
    # ------------------------------------------------------------------ #
    def _handle_select(self, _event: tk.Event) -> None:
        if not self.on_select:
            return
        self.on_select(self.get_selected_alert())


__all__ = ["AlertTable", "COLUMNS"]
