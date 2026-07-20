"""IP geolocation enricher using ip-api.com.

ip-api.com is free for **non-commercial** use and does not require an
API key.  The free endpoint is HTTP-only (no HTTPS) and is rate-limited
to 45 requests per minute from the same IP address — the retry/backoff
logic in :class:`enrichment.base.BaseEnricher` handles 429 responses.

If you need HTTPS or higher rate limits, purchase a commercial key from
ip-api.com and switch the endpoint URL in ``config.ini``.
"""

from __future__ import annotations

from typing import Any, Dict

import requests

from enrichment.base import BaseEnricher
from utils.config import ConfigManager
from data.database import EnrichmentCache


class IPGeolocationEnricher(BaseEnricher):
    """Enrich an IP with country / ISP / ASN info from ip-api.com."""

    name = "ip_geolocation"
    requires_api_key = False

    def __init__(self,
                 config: ConfigManager,
                 cache: EnrichmentCache,
                 session: requests.Session | None = None) -> None:
        super().__init__(config, cache, session)
        # Request the fields we actually use, plus a few useful extras.
        self._endpoint = config.get_endpoint("ip_api")
        self._fields = "status,message,query,country,countryCode,regionName,city,isp,org,as,reverse,hosting"

    def _fetch(self, ip: str) -> Dict[str, Any]:
        url = f"{self._endpoint}{ip}"
        resp = self.session.get(
            url,
            params={"fields": self._fields},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        if data.get("status") != "success":
            raise RuntimeError(
                f"ip-api error for {ip}: {data.get('message', 'unknown')}"
            )
        # Normalize to a stable schema.
        return {
            "ip": data.get("query", ip),
            "country": data.get("country", ""),
            "country_code": data.get("countryCode", ""),
            "region": data.get("regionName", ""),
            "city": data.get("city", ""),
            "isp": data.get("isp", ""),
            "org": data.get("org", ""),
            "asn": data.get("as", ""),
            "is_hosting": bool(data.get("hosting", False)),
            "reverse_dns": data.get("reverse", ""),
        }


__all__ = ["IPGeolocationEnricher"]
