"""
SQL injection and XSS attack detector
"""

import re
from typing import List

class InjectionDetector:
    """Detects injection attacks in URLs and parameters"""

    # Pre-compiled regex patterns
    SQL_INJECTION = re.compile(
        r"(union.*select|select.*from|insert.*into|drop.*table|"
        r"exec\\(|or\\s+1=1|' or |' and |' union |--|;)",
        re.IGNORECASE
    )

    XSS_ATTACK = re.compile(
        r"(<script|javascript:|onerror=|onload=|<iframe|<object|"
        r"eval\\(|document\\.cookie|alert\\()",
        re.IGNORECASE
    )

    DIRECTORY_TRAVERSAL = re.compile(
        r"(\\.\\./|/etc/passwd|/etc/shadow|%2e%2e/|%2e%2e%2f)",
        re.IGNORECASE
    )

    def detect(self, url: str) -> List[str]:
        """
        Detect injection attacks in URL

        Args:
            url: URL or request string to check

        Returns:
            List of detected attack types
        """
        threats = []

        if self.SQL_INJECTION.search(url):
            threats.append('SQL_INJECTION')

        if self.XSS_ATTACK.search(url):
            threats.append('XSS_ATTACK')

        if self.DIRECTORY_TRAVERSAL.search(url):
            threats.append('DIRECTORY_TRAVERSAL')

        return threats
