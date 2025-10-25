"""
CSV export functionality
"""

import csv
from pathlib import Path

class CSVExporter:
    """Export threat data to CSV format"""

    @staticmethod
    def export(threats: list, scored_ips: list, filepath: Path):
        """Export threats and IP scores to CSV"""

        # Export threat details
        threat_file = str(filepath).replace('.csv', '_threats.csv')
        with open(threat_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Timestamp', 'IP', 'Threat Type', 'Severity', 'Details'])

            for threat in threats:
                log = threat['log']
                for t in threat['threats']:
                    writer.writerow([
                        log.get('timestamp', ''),
                        log.get('ip', ''),
                        t['type'],
                        t['severity'],
                        t['details']
                    ])

        # Export IP reputation scores
        ip_file = str(filepath).replace('.csv', '_ip_scores.csv')
        with open(ip_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['IP Address', 'Threat Score', 'Severity', 
                           'Threat Count', 'Attack Types'])

            for ip_data in scored_ips:
                writer.writerow([
                    ip_data['ip'],
                    ip_data['score'],
                    ip_data['severity'],
                    ip_data['threat_count'],
                    ', '.join(ip_data['attack_types'])
                ])
