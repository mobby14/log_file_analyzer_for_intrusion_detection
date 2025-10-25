"""
JSON export functionality
"""

import json
from pathlib import Path
from datetime import datetime

class JSONExporter:
    """Export threat data to JSON format"""

    @staticmethod
    def export(threats: list, scored_ips: list, filepath: Path):
        """Export threats and IP scores to JSON"""

        # Convert datetime objects to strings
        def serialize(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            return str(obj)

        data = {
            'analysis_timestamp': datetime.now().isoformat(),
            'summary': {
                'total_threats': len(threats),
                'unique_ips': len(scored_ips),
                'critical_ips': len([ip for ip in scored_ips 
                                    if ip['severity'] == 'CRITICAL'])
            },
            'threats': threats,
            'ip_scores': scored_ips
        }

        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2, default=serialize)
