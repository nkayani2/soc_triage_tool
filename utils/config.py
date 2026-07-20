"""Configuration management for the SOC Triage Tool.

The configuration is persisted to ``config.ini`` at the project root.
API keys (VirusTotal, AbuseIPDB) are stored in plain text in this file;
this is acceptable for a single-user SOC analyst workstation, but for
multi-user or production deployments you should integrate a secrets
manager (e.g. HashiCorp Vault, AWS Secrets Manager) and adapt
:class:`ConfigManager` accordingly.

Public API
----------
* :class:`ConfigManager` — load/save/query the configuration.
* :data:`DEFAULT_CONFIG_PATH` — default location of ``config.ini``.
"""

from __future__ import annotations

import configparser
import os
from pathlib import Path
from typing import Any, Dict, Optional

from utils.logger import get_logger

logger = get_logger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config.ini"

# Default values used when config.ini does not exist yet.
DEFAULTS: Dict[str, Dict[str, str]] = {
    "api_keys": {
        "virustotal": "",
        "abuseipdb": "",
    },
    "endpoints": {
        "ip_api": "http://ip-api.com/json/",
        "virustotal": "https://www.virustotal.com/api/v3/ip_addresses/",
        "abuseipdb": "https://api.abuseipdb.com/api/v2/check",
        "splunk": "https://localhost:8089",
    },
    "splunk": {
        "username": "",
        "password": "",
        "bearer_token": "",
        "saved_search": "",
        "verify_ssl": "true",
    },
    "scoring": {
        # Weight (0-1) for each component of the composite risk score.
        "severity_weight": "0.35",
        "vt_malicious_weight": "0.30",
        "abuseipdb_weight": "0.25",
        "geolocation_weight": "0.10",
    },
    "thresholds": {
        # Risk score boundaries (0-100) for each priority tier.
        "critical": "80",
        "high": "60",
        "medium": "40",
        "low": "0",
    },
    "cache": {
        # SQLite cache TTL in hours. 0 = cache forever.
        "ttl_hours": "24",
    },
    "ui": {
        "theme": "cyborg",
        "window_width": "1400",
        "window_height": "850",
    },
}


class ConfigManager:
    """Thin wrapper around :class:`configparser.ConfigParser`.

    The configuration is loaded from disk on construction and re-written
    via :meth:`save`.  All values are stored as strings (this is a
    limitation of :mod:`configparser`); numeric helpers are provided for
    convenience.
    """

    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = Path(path) if path else DEFAULT_CONFIG_PATH
        self._parser = configparser.ConfigParser()
        # Make keys case-sensitive.
        self._parser.optionxform = str  # type: ignore[assignment]
        self._load_with_defaults()

    # ------------------------------------------------------------------ #
    # Loading / saving
    # ------------------------------------------------------------------ #
    def _load_with_defaults(self) -> None:
        """Populate the parser with defaults, then overlay the file."""
        # First seed defaults so missing sections never raise.
        for section, options in DEFAULTS.items():
            self._parser[section] = {k: str(v) for k, v in options.items()}

        if self.path.exists():
            try:
                self._parser.read(self.path, encoding="utf-8")
                logger.debug("Configuration loaded from %s", self.path)
            except configparser.Error as exc:
                logger.error("Failed to parse %s: %s", self.path, exc)
        else:
            logger.info("config.ini not found; creating with defaults.")
            self.save()

    def save(self) -> None:
        """Persist the current configuration to ``self.path``."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as fh:
            self._parser.write(fh)
        logger.info("Configuration saved to %s", self.path)

    # ------------------------------------------------------------------ #
    # Generic accessors
    # ------------------------------------------------------------------ #
    def get(self, section: str, option: str, fallback: Optional[str] = None) -> str:
        """Return the string value at ``[section]/option``."""
        try:
            return self._parser.get(section, option)
        except (configparser.NoSectionError, configparser.NoOptionError):
            if fallback is not None:
                return fallback
            raise

    def get_int(self, section: str, option: str, fallback: int = 0) -> int:
        """Return the integer value at ``[section]/option``."""
        try:
            return self._parser.getint(section, option)
        except (configparser.NoSectionError, configparser.NoOptionError, ValueError):
            return fallback

    def get_float(self, section: str, option: str, fallback: float = 0.0) -> float:
        """Return the float value at ``[section]/option``."""
        try:
            return self._parser.getfloat(section, option)
        except (configparser.NoSectionError, configparser.NoOptionError, ValueError):
            return fallback

    def get_bool(self, section: str, option: str, fallback: bool = False) -> bool:
        """Return the boolean value at ``[section]/option``."""
        try:
            return self._parser.getboolean(section, option)
        except (configparser.NoSectionError, configparser.NoOptionError, ValueError):
            return fallback

    def set(self, section: str, option: str, value: Any) -> None:
        """Set ``[section]/option`` to ``value`` (converted to string)."""
        if section not in self._parser:
            self._parser[section] = {}
        self._parser[section][option] = str(value)

    # ------------------------------------------------------------------ #
    # Convenience helpers used by the rest of the application
    # ------------------------------------------------------------------ #
    def get_api_key(self, provider: str) -> str:
        """Return the API key for ``provider`` (e.g. ``'virustotal'``)."""
        return self.get("api_keys", provider, fallback="").strip()

    def set_api_key(self, provider: str, key: str) -> None:
        """Persist an API key for ``provider``."""
        self.set("api_keys", provider, key.strip())

    def get_endpoint(self, provider: str) -> str:
        """Return the configured endpoint URL for ``provider``."""
        return self.get("endpoints", provider).strip()

    def get_scoring_weights(self) -> Dict[str, float]:
        """Return the risk-scoring weights as a dict of floats."""
        return {
            "severity": self.get_float("scoring", "severity_weight"),
            "vt_malicious": self.get_float("scoring", "vt_malicious_weight"),
            "abuseipdb": self.get_float("scoring", "abuseipdb_weight"),
            "geolocation": self.get_float("scoring", "geolocation_weight"),
        }

    def get_thresholds(self) -> Dict[str, int]:
        """Return the risk-score thresholds per priority tier."""
        return {
            "critical": self.get_int("thresholds", "critical", 80),
            "high": self.get_int("thresholds", "high", 60),
            "medium": self.get_int("thresholds", "medium", 40),
            "low": self.get_int("thresholds", "low", 0),
        }

    def as_dict(self) -> Dict[str, Dict[str, str]]:
        """Return the entire config as a nested dict (for the settings UI)."""
        return {s: dict(self._parser.items(s)) for s in self._parser.sections()}


__all__ = ["ConfigManager", "DEFAULT_CONFIG_PATH", "DEFAULTS"]
