"""Composite risk scoring for SOC alerts.

The risk score is a number in the range ``[0, 100]`` computed from four
components:

1. **Severity** of the alert (as reported by the SIEM).
2. **VirusTotal malicious verdict count** for the source IP.
3. **AbuseIPDB confidence score** for the source IP.
4. **Geolocation risk** — a small boost for high-risk countries
   (a curated list maintained below).

Each component is normalized to ``[0, 1]`` and combined using the
configurable weights from ``config.ini``.  The final score is mapped to
a priority tier (``Critical``, ``High``, ``Medium``, ``Low``) using the
thresholds from the configuration.
"""

from __future__ import annotations

from typing import Dict, Optional

from utils.config import ConfigManager
from utils.logger import get_logger

logger = get_logger(__name__)

# A short, opinionated list of "high-risk" source countries commonly
# associated with malicious infrastructure.  Adjust to your environment.
HIGH_RISK_COUNTRIES = {
    "Russia", "China", "North Korea", "Iran", "Belarus",
    "Ukraine", "Nigeria", "Brazil",
}

# Map severities reported by the SIEM to a 0-1 score.  Unknown
# severities default to 0.5 (Medium-ish) so they are not silently
# ignored.
SEVERITY_SCORES: Dict[str, float] = {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.5,
    "moderate": 0.5,
    "low": 0.2,
    "informational": 0.1,
    "info": 0.1,
}


def severity_to_score(severity: str) -> float:
    """Normalize a SIEM severity string to a 0-1 float."""
    if not severity:
        return 0.5
    return SEVERITY_SCORES.get(severity.strip().lower(), 0.5)


def geolocation_to_score(country: Optional[str]) -> float:
    """Return a 0-1 risk score based on the source country.

    Countries in :data:`HIGH_RISK_COUNTRIES` get 1.0; everything else
    gets 0.2 (a small baseline so the component is not binary).
    """
    if not country:
        return 0.2
    return 1.0 if country.strip().title() in HIGH_RISK_COUNTRIES else 0.2


def vt_to_score(malicious_count: Optional[int]) -> float:
    """Normalize VirusTotal malicious count to 0-1.

    The VT v3 API returns the number of engines flagging the IP as
    malicious.  We treat >=10 detections as "definitely malicious" (1.0)
    and scale linearly below that.
    """
    if malicious_count is None:
        return 0.2  # Unknown — neutral baseline.
    if malicious_count <= 0:
        return 0.0
    return min(1.0, malicious_count / 10.0)


def abuseipdb_to_score(confidence: Optional[int]) -> float:
    """Normalize AbuseIPDB confidence score (0-100) to 0-1."""
    if confidence is None:
        return 0.2
    return max(0.0, min(1.0, confidence / 100.0))


class RiskScorer:
    """Compute composite risk scores for SOC alerts.

    The weights and thresholds are loaded from :class:`ConfigManager`,
    so analysts can tune the scoring model without touching code.
    """

    def __init__(self, config: ConfigManager) -> None:
        self.config = config
        self.weights = config.get_scoring_weights()
        self.thresholds = config.get_thresholds()
        # Normalize weights so they always sum to 1.
        total = sum(self.weights.values()) or 1.0
        self.weights = {k: v / total for k, v in self.weights.items()}
        logger.debug("Risk scorer weights: %s", self.weights)

    def score(self,
              severity: str,
              vt_malicious: Optional[int],
              abuseipdb_confidence: Optional[int],
              country: Optional[str]) -> int:
        """Return the composite risk score (0-100, integer).

        Parameters
        ----------
        severity:
            SIEM severity string (e.g. ``'High'``).
        vt_malicious:
            Number of VirusTotal engines flagging the source IP, or
            ``None`` if enrichment has not run / failed.
        abuseipdb_confidence:
            AbuseIPDB confidence score (0-100), or ``None``.
        country:
            Source country name from IP geolocation, or ``None``.
        """
        sev = severity_to_score(severity)
        vt = vt_to_score(vt_malicious)
        ab = abuseipdb_to_score(abuseipdb_confidence)
        geo = geolocation_to_score(country)

        composite = (
            sev * self.weights["severity"]
            + vt * self.weights["vt_malicious"]
            + ab * self.weights["abuseipdb"]
            + geo * self.weights["geolocation"]
        )
        score = int(round(composite * 100))
        score = max(0, min(100, score))
        return score

    def tier(self, score: int) -> str:
        """Map a 0-100 score to a priority tier label."""
        if score >= self.thresholds["critical"]:
            return "Critical"
        if score >= self.thresholds["high"]:
            return "High"
        if score >= self.thresholds["medium"]:
            return "Medium"
        return "Low"


__all__ = [
    "RiskScorer",
    "severity_to_score",
    "geolocation_to_score",
    "vt_to_score",
    "abuseipdb_to_score",
    "HIGH_RISK_COUNTRIES",
]
