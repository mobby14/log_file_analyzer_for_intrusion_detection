"""
IP reputation scoring system
"""

from typing import Tuple

class IPReputationScorer:
    """Calculate threat scores for IP addresses"""

    @staticmethod
    def calculate_score(
        blacklist_hits: int = 0,
        failed_attempts: int = 0,
        attack_types: int = 0,
        requests_per_minute: float = 0
    ) -> Tuple[int, str]:
        """
        Calculate comprehensive threat score

        Args:
            blacklist_hits: Number of blacklist matches
            failed_attempts: Number of failed attempts
            attack_types: Number of unique attack types
            requests_per_minute: Request rate

        Returns:
            Tuple of (score, severity_level)
        """
        score = (
            (blacklist_hits * 10) +
            (failed_attempts * 5) +
            (attack_types * 3) +
            (int(requests_per_minute / 10) * 2)
        )

        if score >= 50:
            severity = "CRITICAL"
        elif score >= 30:
            severity = "HIGH"
        elif score >= 15:
            severity = "MEDIUM"
        elif score >= 5:
            severity = "LOW"
        else:
            severity = "INFO"

        return score, severity
