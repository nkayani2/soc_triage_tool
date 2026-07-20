"""Theme, color palette, and shared style helpers for the GUI.

We use ``ttkbootstrap`` with the ``cyborg`` theme as a base and then
overlay a custom SOC-inspired palette (dark navy background, cyan
accents, traffic-light risk colors).
"""

from __future__ import annotations

from typing import Dict

# Try to import ttkbootstrap; if missing, fall back to plain ttk so the
# tool at least runs (with a less polished look).
try:
    import ttkbootstrap as ttkb  # type: ignore
    from ttkbootstrap.constants import (  # type: ignore
        SUCCESS, INFO, WARNING, DANGER, PRIMARY, SECONDARY, DARK, LIGHT,
    )
    HAVE_TTKBOOTSTRAP = True
except ImportError:  # pragma: no cover
    import tkinter.ttk as ttkb  # type: ignore
    SUCCESS = INFO = WARNING = DANGER = PRIMARY = SECONDARY = DARK = LIGHT = ""
    HAVE_TTKBOOTSTRAP = False


# SOC palette --------------------------------------------------------------
COLORS: Dict[str, str] = {
    "bg":            "#0F1419",  # main background
    "bg_panel":      "#1A2332",  # side panels
    "bg_table":      "#141C28",  # table background
    "bg_table_alt":  "#1A2332",  # alternating row
    "fg":            "#E6E6E6",  # primary text
    "fg_muted":      "#8AA0B6",  # secondary text
    "accent":        "#4FC3F7",  # cyan accent (buttons, highlights)
    "accent_dark":   "#0F4C81",  # darker accent (headers)
    "border":        "#2A3441",  # panel borders

    # Risk tier colors
    "critical":      "#E53935",
    "high":          "#FB8C00",
    "medium":        "#FDD835",
    "low":           "#43A047",

    # Status colors
    "escalated":     "#E53935",
    "false_positive":"#43A047",
    "resolved":      "#4FC3F7",
    "unreviewed":    "#8AA0B6",
}

# Map risk tier -> COLORS key.
TIER_COLOR_KEY = {
    "Critical": "critical",
    "High":     "high",
    "Medium":   "medium",
    "Low":      "low",
}

# Map status -> COLORS key.
STATUS_COLOR_KEY = {
    "Escalated":      "escalated",
    "False Positive": "false_positive",
    "Resolved":       "resolved",
    "Unreviewed":     "unreviewed",
}


def tier_color(tier: str) -> str:
    """Return the hex color for a risk tier label."""
    return COLORS.get(TIER_COLOR_KEY.get(tier, "low"), COLORS["low"])


def status_color(status: str) -> str:
    """Return the hex color for a triage status label."""
    return COLORS.get(STATUS_COLOR_KEY.get(status, "unreviewed"),
                      COLORS["unreviewed"])


def apply_theme() -> str:
    """Apply the ttkbootstrap theme and return its name.

    Falls back to the default ttk theme if ttkbootstrap is unavailable.
    """
    if HAVE_TTKBOOTSTRAP:
        style = ttkb.Style("cyborg")
        # Tweak a few colors to match the SOC palette more closely.
        try:
            style.configure("TFrame", background=COLORS["bg"])
            style.configure("Panel.TFrame", background=COLORS["bg_panel"])
            style.configure("TLabel",
                            background=COLORS["bg"],
                            foreground=COLORS["fg"],
                            font=("Segoe UI", 10))
            style.configure("Title.TLabel",
                            background=COLORS["bg"],
                            foreground=COLORS["accent"],
                            font=("Segoe UI", 14, "bold"))
            style.configure("Muted.TLabel",
                            background=COLORS["bg"],
                            foreground=COLORS["fg_muted"],
                            font=("Segoe UI", 9))
            style.configure("Treeview",
                            background=COLORS["bg_table"],
                            foreground=COLORS["fg"],
                            fieldbackground=COLORS["bg_table"],
                            bordercolor=COLORS["border"],
                            rowheight=24,
                            font=("Segoe UI", 9))
            style.configure("Treeview.Heading",
                            background=COLORS["accent_dark"],
                            foreground="#FFFFFF",
                            font=("Segoe UI", 10, "bold"),
                            relief="flat")
            style.map("Treeview",
                      background=[("selected", COLORS["accent_dark"])],
                      foreground=[("selected", "#FFFFFF")])
        except Exception:
            # ttkbootstrap versions differ; ignore style errors.
            pass
        return "cyborg"
    return "default"


__all__ = [
    "COLORS",
    "TIER_COLOR_KEY",
    "STATUS_COLOR_KEY",
    "tier_color",
    "status_color",
    "apply_theme",
    "HAVE_TTKBOOTSTRAP",
    "SUCCESS",
    "INFO",
    "WARNING",
    "DANGER",
    "PRIMARY",
    "SECONDARY",
    "DARK",
    "LIGHT",
]
