"""
Utility helper functions
"""

import logging
from datetime import datetime

def setup_logging(verbose: bool = False):
    """Setup logging configuration"""
    level = logging.DEBUG if verbose else logging.INFO

    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    return logging.getLogger(__name__)

def print_banner():
    """Print application banner"""
    banner = """
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║        LOG FILE ANALYZER FOR INTRUSION DETECTION             ║
║                                                              ║
║              Detect • Analyze • Protect                      ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)

def print_summary(threats: list, scored_ips: list):
    """Print analysis summary"""
    print("\n" + "="*70)
    print("ANALYSIS SUMMARY".center(70))
    print("="*70)

    print(f"\nTotal Threat Events: {len(threats)}")
    print(f"Unique Attacking IPs: {len(scored_ips)}")

    if scored_ips:
        critical = len([ip for ip in scored_ips if ip['severity'] == 'CRITICAL'])
        high = len([ip for ip in scored_ips if ip['severity'] == 'HIGH'])
        medium = len([ip for ip in scored_ips if ip['severity'] == 'MEDIUM'])

        print(f"\nSeverity Breakdown:")
        print(f"  CRITICAL: {critical}")
        print(f"  HIGH:     {high}")
        print(f"  MEDIUM:   {medium}")

        print(f"\nTop 5 Attacking IPs:")
        for i, ip_data in enumerate(scored_ips[:5], 1):
            print(f"  {i}. {ip_data['ip']} - Score: {ip_data['score']} "
                  f"({ip_data['severity']}) - Attacks: {ip_data['threat_count']}")

        # Threat types
        threat_types = set()
        for ip_data in scored_ips:
            threat_types.update(ip_data['attack_types'])

        if threat_types:
            print(f"\nDetected Attack Types:")
            for threat in sorted(threat_types):
                print(f"  • {threat}")

    print("\n" + "="*70 + "\n")
