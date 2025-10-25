"""
Base parser class for all log parsers
"""

from abc import ABC, abstractmethod
from typing import List, Dict

class BaseLogParser(ABC):
    """Abstract base class for log parsers"""

    def __init__(self):
        self.parsed_logs = []

    def parse_file(self, filepath: str) -> List[Dict]:
        """Parse entire log file"""
        self.parsed_logs = []

        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        parsed = self.parse_line(line)
                        if parsed:
                            self.parsed_logs.append(parsed)
        except Exception as e:
            print(f"Error reading file: {e}")
            return []

        return self.parsed_logs

    @abstractmethod
    def parse_line(self, line: str) -> Dict:
        """Override in subclass to parse individual log lines"""
        pass
