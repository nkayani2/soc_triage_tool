"""Settings dialog for API keys and other configuration.

The dialog edits the live :class:`ConfigManager`; changes are persisted
to ``config.ini`` only when the user clicks **Save**.
"""

from __future__ import annotations

from typing import Optional

import tkinter as tk
from tkinter import ttk, messagebox

from utils.config import ConfigManager
from utils.logger import get_logger

logger = get_logger(__name__)


class SettingsDialog(tk.Toplevel):
    """Modal dialog for editing application settings."""

    def __init__(self, parent: tk.Widget, config: ConfigManager) -> None:
        super().__init__(parent)
        self.config = config
        self.title("Settings — API Keys & Configuration")
        self.geometry("620x620")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        self._build_widgets()
        self._load_values()

    # ------------------------------------------------------------------ #
    # Construction
    # ------------------------------------------------------------------ #
    def _build_widgets(self) -> None:
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=10, pady=10)

        # ----- API Keys tab ----------------------------------------------
        api_tab = ttk.Frame(nb, padding=12)
        nb.add(api_tab, text="API Keys")

        ttk.Label(api_tab,
                  text="VirusTotal",
                  style="Title.TLabel").pack(anchor="w", pady=(0, 4))
        ttk.Label(api_tab,
                  text="Sign up for a free key at "
                       "https://www.virustotal.com/gui/my-apikey",
                  style="Muted.TLabel").pack(anchor="w", pady=(0, 4))
        self.vt_key_var = tk.StringVar()
        ttk.Entry(api_tab, textvariable=self.vt_key_var, show="*",
                  width=70).pack(fill="x", pady=(0, 12))

        ttk.Label(api_tab,
                  text="AbuseIPDB",
                  style="Title.TLabel").pack(anchor="w", pady=(0, 4))
        ttk.Label(api_tab,
                  text="Sign up for a free key at "
                       "https://www.abuseipdb.com/account/api",
                  style="Muted.TLabel").pack(anchor="w", pady=(0, 4))
        self.abuse_key_var = tk.StringVar()
        ttk.Entry(api_tab, textvariable=self.abuse_key_var, show="*",
                  width=70).pack(fill="x", pady=(0, 12))

        # Toggle for showing the keys in clear text.
        self.show_keys_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(api_tab, text="Show keys in clear text",
                        variable=self.show_keys_var,
                        command=self._toggle_key_visibility).pack(anchor="w")

        # ----- Splunk tab ------------------------------------------------
        splunk_tab = ttk.Frame(nb, padding=12)
        nb.add(splunk_tab, text="Splunk")

        self.splunk_url_var = tk.StringVar()
        self.splunk_user_var = tk.StringVar()
        self.splunk_pass_var = tk.StringVar()
        self.splunk_token_var = tk.StringVar()
        self.splunk_search_var = tk.StringVar()
        self.splunk_verify_var = tk.BooleanVar()

        for label, var, show in [
            ("Splunk URL (https://host:8089)", self.splunk_url_var, ""),
            ("Username", self.splunk_user_var, ""),
            ("Password", self.splunk_pass_var, "*"),
            ("Bearer Token (optional, overrides user/pass)",
             self.splunk_token_var, "*"),
            ("Saved Search Name", self.splunk_search_var, ""),
        ]:
            ttk.Label(splunk_tab, text=label).pack(anchor="w", pady=(4, 0))
            ttk.Entry(splunk_tab, textvariable=var, show=show or "",
                      width=60).pack(fill="x")
        ttk.Checkbutton(splunk_tab, text="Verify SSL certificate",
                        variable=self.splunk_verify_var).pack(anchor="w",
                                                              pady=(8, 0))

        # ----- Scoring tab -----------------------------------------------
        scoring_tab = ttk.Frame(nb, padding=12)
        nb.add(scoring_tab, text="Risk Scoring")

        ttk.Label(scoring_tab,
                  text="Component weights (will be normalized to sum to 1):",
                  style="Muted.TLabel").pack(anchor="w", pady=(0, 8))

        self.weight_vars = {}
        for label, key in [
            ("Severity weight", "severity_weight"),
            ("VirusTotal malicious weight", "vt_malicious_weight"),
            ("AbuseIPDB confidence weight", "abuseipdb_weight"),
            ("Geolocation weight", "geolocation_weight"),
        ]:
            row = ttk.Frame(scoring_tab)
            row.pack(fill="x", pady=2)
            ttk.Label(row, text=label, width=28).pack(side="left")
            var = tk.StringVar()
            self.weight_vars[key] = var
            ttk.Entry(row, textvariable=var, width=10).pack(side="left")

        ttk.Separator(scoring_tab, orient="horizontal").pack(fill="x",
                                                             pady=12)
        ttk.Label(scoring_tab,
                  text="Tier thresholds (0-100, must be descending):",
                  style="Muted.TLabel").pack(anchor="w", pady=(0, 8))

        self.threshold_vars = {}
        for label, key in [
            ("Critical ≥", "critical"),
            ("High ≥", "high"),
            ("Medium ≥", "medium"),
            ("Low ≥", "low"),
        ]:
            row = ttk.Frame(scoring_tab)
            row.pack(fill="x", pady=2)
            ttk.Label(row, text=label, width=18).pack(side="left")
            var = tk.StringVar()
            self.threshold_vars[key] = var
            ttk.Entry(row, textvariable=var, width=8).pack(side="left")

        ttk.Separator(scoring_tab, orient="horizontal").pack(fill="x",
                                                             pady=12)
        ttk.Label(scoring_tab, text="Cache TTL (hours, 0 = forever):",
                  style="Muted.TLabel").pack(anchor="w", pady=(0, 4))
        self.cache_ttl_var = tk.StringVar()
        ttk.Entry(scoring_tab, textvariable=self.cache_ttl_var,
                  width=10).pack(anchor="w")

        # ----- Buttons ---------------------------------------------------
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill="x", padx=10, pady=(0, 10))
        ttk.Button(btn_frame, text="Cancel",
                   command=self.destroy).pack(side="right", padx=(4, 0))
        ttk.Button(btn_frame, text="Save",
                   command=self._save).pack(side="right")
        ttk.Button(btn_frame, text="Clear Cache",
                   command=self._clear_cache).pack(side="left")

    # ------------------------------------------------------------------ #
    # Load / save
    # ------------------------------------------------------------------ #
    def _load_values(self) -> None:
        self.vt_key_var.set(self.config.get_api_key("virustotal"))
        self.abuse_key_var.set(self.config.get_api_key("abuseipdb"))

        self.splunk_url_var.set(self.config.get_endpoint("splunk"))
        self.splunk_user_var.set(self.config.get("splunk", "username",
                                                 fallback=""))
        self.splunk_pass_var.set(self.config.get("splunk", "password",
                                                 fallback=""))
        self.splunk_token_var.set(self.config.get("splunk", "bearer_token",
                                                  fallback=""))
        self.splunk_search_var.set(self.config.get("splunk", "saved_search",
                                                   fallback=""))
        self.splunk_verify_var.set(
            self.config.get_bool("splunk", "verify_ssl", fallback=True))

        for key, var in self.weight_vars.items():
            var.set(str(self.config.get_float("scoring", key)))
        for key, var in self.threshold_vars.items():
            var.set(str(self.config.get_int("thresholds", key)))
        self.cache_ttl_var.set(
            str(self.config.get_int("cache", "ttl_hours", fallback=24)))

    def _toggle_key_visibility(self) -> None:
        show = "" if self.show_keys_var.get() else "*"
        # Re-create the entries is overkill; instead update their show attr.
        # ttk.Entry.show is not directly settable, so we walk children.
        for entry in self.winfo_children():
            if isinstance(entry, ttk.Entry):
                entry.configure(show=show)

    def _save(self) -> None:
        try:
            self.config.set_api_key("virustotal", self.vt_key_var.get())
            self.config.set_api_key("abuseipdb", self.abuse_key_var.get())

            self.config.set("endpoints", "splunk",
                            self.splunk_url_var.get().strip())
            self.config.set("splunk", "username",
                            self.splunk_user_var.get().strip())
            self.config.set("splunk", "password",
                            self.splunk_pass_var.get())
            self.config.set("splunk", "bearer_token",
                            self.splunk_token_var.get().strip())
            self.config.set("splunk", "saved_search",
                            self.splunk_search_var.get().strip())
            self.config.set("splunk", "verify_ssl",
                            str(self.splunk_verify_var.get()))

            for key, var in self.weight_vars.items():
                val = float(var.get())
                if val < 0:
                    raise ValueError(f"Weight {key} cannot be negative.")
                self.config.set("scoring", key, val)
            for key, var in self.threshold_vars.items():
                val = int(var.get())
                if not 0 <= val <= 100:
                    raise ValueError(f"Threshold {key} must be 0-100.")
                self.config.set("thresholds", key, val)
            self.config.set("cache", "ttl_hours",
                            int(self.cache_ttl_var.get()))

            self.config.save()
            logger.info("Settings saved.")
            messagebox.showinfo("Settings", "Settings saved successfully.",
                                parent=self)
            self.destroy()
        except ValueError as exc:
            messagebox.showerror("Invalid input", str(exc), parent=self)
        except Exception as exc:
            logger.exception("Failed to save settings.")
            messagebox.showerror("Error", f"Failed to save: {exc}",
                                 parent=self)

    def _clear_cache(self) -> None:
        """Hook for clearing the enrichment cache (wired up by parent)."""
        # Lazy: delegate via attribute set by the parent.
        cb = getattr(self, "_clear_cache_callback", None)
        if cb is None:
            messagebox.showinfo("Cache",
                                "Cache clear not wired up yet.",
                                parent=self)
            return
        if messagebox.askyesno("Confirm",
                                "Clear all cached enrichment results?",
                                parent=self):
            deleted = cb()
            messagebox.showinfo("Cache",
                                f"Cleared {deleted} entries.",
                                parent=self)


__all__ = ["SettingsDialog"]
