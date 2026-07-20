"""Abstract base class for all enrichers.

The contract is intentionally minimal:

* ``name`` — short identifier used as the cache key and in the UI.
* ``requires_api_key`` — whether the enricher needs an API key.
* ``enrich(ip)`` — return a dict of normalized fields, or raise
  :class:`EnrichmentError`.

All enrichers receive the :class:`ConfigManager`, the
:class:`EnrichmentCache`, and a :class:`requests.Session` on
construction so they can share HTTP connections and benefit from the
cache transparently via :meth:`BaseEnricher._cached_or_fetch`.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

import requests

from data.database import EnrichmentCache
from utils.config import ConfigManager
from utils.logger import get_logger


class EnrichmentError(RuntimeError):
    """Raised when an enricher fails irrecoverably."""


class BaseEnricher(ABC):
    """Common scaffolding for all enrichers."""

    #: Short identifier (used as cache key + in the UI).
    name: str = "base"
    #: Whether this enricher requires an API key.
    requires_api_key: bool = False
    #: Maximum number of retry attempts on rate-limit / transient errors.
    max_retries: int = 3
    #: Base delay (seconds) for exponential backoff.
    backoff_base: float = 1.0

    def __init__(self,
                 config: ConfigManager,
                 cache: EnrichmentCache,
                 session: Optional[requests.Session] = None) -> None:
        self.config = config
        self.cache = cache
        self.session = session or requests.Session()
        self.logger = get_logger(f"enrichment.{self.name}")

    # ------------------------------------------------------------------ #
    # Template method
    # ------------------------------------------------------------------ #
    def enrich(self, ip: str) -> Dict[str, Any]:
        """Return enriched data for ``ip``.

        Subclasses implement :meth:`_fetch`; this base class handles
        caching, retries with exponential backoff, and uniform error
        handling.
        """
        if not ip:
            return {}

        # Try the cache first.
        cached = self.cache.get(ip, self.name)
        if cached is not None:
            self.logger.debug("Cache hit for %s/%s", ip, self.name)
            return cached

        if self.requires_api_key and not self._get_api_key():
            raise EnrichmentError(
                f"{self.name} requires an API key but none is configured. "
                "Open Settings → API Keys to add one."
            )

        # Retry loop with exponential backoff.
        last_exc: Optional[Exception] = None
        for attempt in range(1, self.max_retries + 1):
            try:
                payload = self._fetch(ip)
                # Only cache successful, non-empty responses.
                if payload:
                    self.cache.put(ip, self.name, payload)
                return payload
            except requests.HTTPError as exc:
                last_exc = exc
                status = exc.response.status_code if exc.response is not None else 0
                if status == 429:
                    # Rate limited — back off and retry.
                    delay = self.backoff_base * (2 ** (attempt - 1))
                    self.logger.warning(
                        "%s rate-limited on %s; backing off %.1fs (attempt %d/%d)",
                        self.name, ip, delay, attempt, self.max_retries,
                    )
                    time.sleep(delay)
                    continue
                if 500 <= status < 600 and attempt < self.max_retries:
                    delay = self.backoff_base * (2 ** (attempt - 1))
                    self.logger.warning(
                        "%s server error %d on %s; retrying in %.1fs",
                        self.name, status, ip, delay,
                    )
                    time.sleep(delay)
                    continue
                raise EnrichmentError(f"{self.name} HTTP {status} for {ip}: {exc}") from exc
            except requests.RequestException as exc:
                last_exc = exc
                if attempt < self.max_retries:
                    delay = self.backoff_base * (2 ** (attempt - 1))
                    self.logger.warning(
                        "%s network error on %s: %s; retrying in %.1fs",
                        self.name, ip, exc, delay,
                    )
                    time.sleep(delay)
                    continue
                raise EnrichmentError(f"{self.name} network error for {ip}: {exc}") from exc

        # Should not be reachable, but keep the linter happy.
        raise EnrichmentError(
            f"{self.name} failed for {ip} after {self.max_retries} attempts: {last_exc}"
        )

    # ------------------------------------------------------------------ #
    # Hooks for subclasses
    # ------------------------------------------------------------------ #
    @abstractmethod
    def _fetch(self, ip: str) -> Dict[str, Any]:
        """Perform the actual HTTP request and return a normalized dict."""
        raise NotImplementedError

    def _get_api_key(self) -> str:
        """Return the API key for this enricher (empty string if none)."""
        return self.config.get_api_key(self.name)


__all__ = ["BaseEnricher", "EnrichmentError"]
