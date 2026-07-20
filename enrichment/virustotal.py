"""VirusTotal v3 IP reputation enricher.

Requires a free VirusTotal API key (sign up at
https://www.virustotal.com/gui/my-apikey).  The free tier allows 4
requests per minute and 500 per day — be mindful of this when batch
enriching large alert sets.

Returned fields
---------------
* ``malicious`` — number of AV engines flagging the IP as malicious.
* ``suspicious`` — number of engines flagging it as suspicious.
* ``harmless`` — number of engines considering it harmless.
* ``reputation`` — VT community reputation (can be negative).
* ``last_analysis_date`` — ISO timestamp of the most recent analysis.
* ``link`` — human-readable URL to the VT report.
"""

from __future__ import annotations

from typing import Any, Dict

import requests

from enrichment.base import BaseEnricher
from utils.config import ConfigManager
from data.database import EnrichmentCache


class VirusTotalEnricher(BaseEnricher):
    """Query the VirusTotal v3 API for IP reputation."""

    name = "virustotal"
    requires_api_key = True

    def __init__(self,
                 config: ConfigManager,
                 cache: EnrichmentCache,
                 session: requests.Session | None = None) -> None:
        super().__init__(config, cache, session)
        self._endpoint = config.get_endpoint("virustotal")

    def _fetch(self, ip: str) -> Dict[str, Any]:
        url = f"{self._endpoint}{ip}"
        resp = self.session.get(
            url,
            headers={"x-apikey": self._get_api_key(),
                     "Accept": "application/json"},
            timeout=15,
        )
        resp.raise_for_status()
        body = resp.json().get("data", {})

        attrs = body.get("attributes", {})
        last_stats = attrs.get("last_analysis_stats", {}) or {}
        last_analysis = attrs.get("last_analysis_date")

        return {
            "ip": ip,
            "malicious": int(last_stats.get("malicious", 0)),
            "suspicious": int(last_stats.get("suspicious", 0)),
            "harmless": int(last_stats.get("harmless", 0)),
            "undetected": int(last_stats.get("undetected", 0)),
            "reputation": int(attrs.get("reputation", 0)),
            "last_analysis_date": last_analysis,
            "link": f"https://www.virustotal.com/gui/ip-address/{ip}",
        }


__all__ = ["VirusTotalEnricher"]
