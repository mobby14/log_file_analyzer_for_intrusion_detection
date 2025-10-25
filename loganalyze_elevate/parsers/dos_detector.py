"""
DoS/DDoS attack detector based on request rate
"""

from datetime import datetime, timedelta
from collections import defaultdict
from typing import Tuple

class DoSDetector:
    """Detects potential DoS attacks based on request rate"""

    def __init__(self, window_seconds: int = 60, threshold: int = 10):
        """
        Args:
            window_seconds: Time window in seconds
            threshold: Number of requests to trigger alert
        """
        self.window_seconds = window_seconds
        self.threshold = threshold
        self.requests = defaultdict(list)

    def check(self, ip: str, timestamp: datetime) -> Tuple[bool, int]:
        """
        Check if IP has exceeded DoS threshold

        Args:
            ip: IP address
            timestamp: Timestamp of request

        Returns:
            Tuple of (is_dos, request_count)
        """
        # Add new request
        self.requests[ip].append(timestamp)

        # Keep only requests within time window
        cutoff = timestamp - timedelta(seconds=self.window_seconds)
        self.requests[ip] = [
            t for t in self.requests[ip] if t > cutoff
        ]

        request_count = len(self.requests[ip])
        is_dos = request_count >= self.threshold

        return is_dos, request_count
