"""AbuseIPDB v2 IP reputation enricher.

Requires a free AbuseIPDB API key (sign up at
https://www.abuseipdb.com/account/api).  The free tier allows 1,000
checks per day.

Returned fields
---------------
* ``abuse_confidence_score`` — 0-100 confidence score (the headline metric).
* ``total_reports`` — number of abuse reports filed against this IP.
* ``country_code`` — ISO country code from AbuseIPDB.
* ``usage_type`` — e.g. ``'Data Center/Web Hosting/Transit'``.
* ``isp`` — ISP name (if reported).
* ``domain`` — associated domain (if reported).
* ``categories`` — comma-separated list of abuse categories.
"""

from __future__ import annotations

from typing import Any, Dict

import requests

from enrichment.base import BaseEnricher
from utils.config import ConfigManager
from data.database import EnrichmentCache

# AbuseIPDB category codes -> human-readable names (subset).
# https://www.abuseipdb.com/categories
_CATEGORY_NAMES: Dict[int, str] = {
    1: "DNS Compromise",
    2: "DNS Poisoning",
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    8: "Fraud VoIP",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted",
}


class AbuseIPDBEnricher(BaseEnricher):
    """Query the AbuseIPDB v2 API for IP abuse reputation."""

    name = "abuseipdb"
    requires_api_key = True

    def __init__(self,
                 config: ConfigManager,
                 cache: EnrichmentCache,
                 session: requests.Session | None = None) -> None:
        super().__init__(config, cache, session)
        self._endpoint = config.get_endpoint("abuseipdb")

    def _fetch(self, ip: str) -> Dict[str, Any]:
        resp = self.session.get(
            self._endpoint,
            headers={
                "Key": self._get_api_key(),
                "Accept": "application/json",
            },
            params={
                "ipAddress": ip,
                "maxAgeInDays": 90,
                "verbose": "true",
            },
            timeout=15,
        )
        resp.raise_for_status()
        body = resp.json().get("data", {})

        # Collect category IDs from individual abuse reports.
        category_ids: list[int] = []
        for report in body.get("reports", []) or []:
            cid = report.get("categoryId")
            if cid is not None:
                try:
                    category_ids.append(int(cid))
                except (TypeError, ValueError):
                    pass

        # Deduplicate category names while preserving order.
        seen = set()
        categories: list[str] = []
        for cid in category_ids:
            name = _CATEGORY_NAMES.get(int(cid), f"Category {cid}")
            if name not in seen:
                seen.add(name)
                categories.append(name)

        return {
            "ip": ip,
            "abuse_confidence_score": int(body.get("abuseConfidenceScore", 0)),
            "total_reports": int(body.get("totalReports", 0)),
            "num_distinct_users": int(body.get("numDistinctUsers", 0)),
            "country_code": body.get("countryCode", ""),
            "usage_type": body.get("usageType", ""),
            "isp": body.get("isp", ""),
            "domain": body.get("domain", ""),
            "categories": ", ".join(categories),
            "link": f"https://www.abuseipdb.com/check/{ip}",
        }


__all__ = ["AbuseIPDBEnricher"]
