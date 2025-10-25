#!/usr/bin/env python3
"""
Log File Analyzer for Intrusion Detection
Main entry point with CLI interface
"""

import argparse
import sys
from pathlib import Path
from datetime import datetime

from parsers.apache_parser import ApacheLogParser
from parsers.ssh_parser import SSHLogParser
from detectors.brute_force import BruteForceDetector
from detectors.dos_detector import DoSDetector
from detectors.injection_detector import InjectionDetector
from intelligence.ip_reputation import IPReputationScorer
from visualization.charts import ChartGenerator
from export.csv_exporter import CSVExporter
from export.json_exporter import JSONExporter
from utils.helpers import setup_logging, print_banner, print_summary

def create_parser():
    """Create command-line argument parser"""
    parser = argparse.ArgumentParser(
        description='Log File Analyzer for Intrusion Detection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py -f apache_access.log -t apache
  python main.py -f ssh_auth.log -t ssh --bf-threshold 5
  python main.py -f access.log --format json --visualize
        """
    )

    # Input arguments
    parser.add_argument('-f', '--file', required=True,
                        help='Log file to analyze')
    parser.add_argument('-t', '--type', choices=['apache', 'ssh'],
                        required=True, help='Log type')

    # Detection thresholds
    parser.add_argument('--bf-threshold', type=int, default=5,
                        help='Brute-force attempts threshold (default: 5)')
    parser.add_argument('--dos-threshold', type=int, default=10,
                        help='DoS requests threshold (default: 10)')

    # Output options
    parser.add_argument('-o', '--output', default='output',
                        help='Output directory (default: output)')
    parser.add_argument('--format', choices=['csv', 'json', 'both'],
                        default='both', help='Output format')
    parser.add_argument('--visualize', action='store_true',
                        help='Generate visualization charts')

    # Verbosity
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose output')

    return parser

def main():
    """Main execution function"""
    parser = create_parser()
    args = parser.parse_args()

    # Setup
    logger = setup_logging(verbose=args.verbose)
    print_banner()

    # Create output directory
    output_dir = Path(args.output)
    output_dir.mkdir(exist_ok=True)

    # Check if file exists
    if not Path(args.file).exists():
        logger.error(f"File not found: {args.file}")
        sys.exit(1)

    logger.info(f"Analyzing log file: {args.file}")
    logger.info(f"Log type: {args.type}")

    # Parse logs
    if args.type == 'apache':
        log_parser = ApacheLogParser()
    else:
        log_parser = SSHLogParser()

    parsed_logs = log_parser.parse_file(args.file)
    logger.info(f"Parsed {len(parsed_logs)} log entries")

    if len(parsed_logs) == 0:
        logger.error("No valid log entries found!")
        sys.exit(1)

    # Initialize detectors
    bf_detector = BruteForceDetector(threshold=args.bf_threshold)
    dos_detector = DoSDetector(threshold=args.dos_threshold)
    injection_detector = InjectionDetector()
    ip_scorer = IPReputationScorer()

    # Analyze logs
    threats = []
    for log_entry in parsed_logs:
        threat_entry = {'log': log_entry, 'threats': []}

        # Brute-force detection
        if args.type == 'ssh' or (args.type == 'apache' and 
                                   log_entry.get('status') in ['401', '403']):
            is_bf, count = bf_detector.check(log_entry['ip'], 
                                             log_entry['timestamp'])
            if is_bf:
                threat_entry['threats'].append({
                    'type': 'BRUTE_FORCE',
                    'severity': 'HIGH',
                    'details': f'Failed attempts: {count}'
                })

        # DoS detection
        is_dos, rpm = dos_detector.check(log_entry['ip'], 
                                         log_entry['timestamp'])
        if is_dos:
            threat_entry['threats'].append({
                'type': 'DOS_ATTACK',
                'severity': 'CRITICAL',
                'details': f'Requests: {rpm} in window'
            })

        # Injection detection (Apache only)
        if args.type == 'apache':
            injections = injection_detector.detect(log_entry.get('url', ''))
            for inj_type in injections:
                threat_entry['threats'].append({
                    'type': inj_type,
                    'severity': 'HIGH',
                    'details': f'Malicious pattern detected in URL'
                })

        if threat_entry['threats']:
            threats.append(threat_entry)

    logger.info(f"Detected {len(threats)} threat events")

    # Calculate IP reputation scores
    ip_stats = {}
    for threat in threats:
        ip = threat['log']['ip']
        if ip not in ip_stats:
            ip_stats[ip] = {
                'ip': ip,
                'threats': [],
                'count': 0
            }
        ip_stats[ip]['threats'].extend([t['type'] for t in threat['threats']])
        ip_stats[ip]['count'] += 1

    # Score IPs
    scored_ips = []
    for ip, data in ip_stats.items():
        score, severity = ip_scorer.calculate_score(
            failed_attempts=data['count'],
            attack_types=len(set(data['threats']))
        )
        scored_ips.append({
            'ip': ip,
            'score': score,
            'severity': severity,
            'threat_count': data['count'],
            'attack_types': list(set(data['threats']))
        })

    scored_ips.sort(key=lambda x: x['score'], reverse=True)

    # Print summary
    print_summary(threats, scored_ips)

    # Export results
    if args.format in ['csv', 'both']:
        csv_file = output_dir / f"threats_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        CSVExporter.export(threats, scored_ips, csv_file)
        logger.info(f"CSV report saved to: {csv_file}")

    if args.format in ['json', 'both']:
        json_file = output_dir / f"threats_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        JSONExporter.export(threats, scored_ips, json_file)
        logger.info(f"JSON report saved to: {json_file}")

    # Generate visualizations
    if args.visualize:
        chart_gen = ChartGenerator(output_dir)
        chart_gen.generate_all(threats, scored_ips, args.type)
        logger.info(f"Charts saved to: {output_dir}")

    logger.info("Analysis complete!")
    return 0

if __name__ == '__main__':
    sys.exit(main())
