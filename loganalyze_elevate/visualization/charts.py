"""
Visualization chart generator
"""

import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt
import seaborn as sns
from collections import Counter
from pathlib import Path

class ChartGenerator:
    """Generate visualization charts for threat data"""

    def __init__(self, output_dir: Path):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

        # Set style
        sns.set_style('whitegrid')
        plt.rcParams['figure.figsize'] = (10, 6)

    def generate_all(self, threats: list, scored_ips: list, log_type: str):
        """Generate all visualization charts"""
        self.plot_threat_timeline(threats)
        self.plot_top_attackers(scored_ips)
        self.plot_threat_distribution(threats)
        self.plot_severity_distribution(scored_ips)

    def plot_threat_timeline(self, threats: list):
        """Plot threat frequency over time"""
        if not threats:
            return

        timestamps = [t['log'].get('timestamp') for t in threats 
                     if t['log'].get('timestamp')]

        if not timestamps:
            return

        plt.figure(figsize=(12, 6))
        plt.hist(timestamps, bins=20, color='#e74c3c', alpha=0.7, edgecolor='black')
        plt.title('Threat Detection Timeline', fontsize=16, fontweight='bold')
        plt.xlabel('Time', fontsize=12)
        plt.ylabel('Number of Threats', fontsize=12)
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig(self.output_dir / 'threat_timeline.png', dpi=300)
        plt.close()

    def plot_top_attackers(self, scored_ips: list, top_n: int = 10):
        """Plot top attacking IPs"""
        if not scored_ips:
            return

        # Get top N IPs
        top_ips = scored_ips[:min(top_n, len(scored_ips))]

        ips = [ip['ip'] for ip in top_ips]
        scores = [ip['score'] for ip in top_ips]
        colors = ['#e74c3c' if ip['severity'] == 'CRITICAL' 
                 else '#f39c12' if ip['severity'] == 'HIGH'
                 else '#f1c40f' for ip in top_ips]

        plt.figure(figsize=(12, 8))
        bars = plt.barh(ips, scores, color=colors, edgecolor='black')
        plt.title(f'Top {len(top_ips)} Attacking IPs by Threat Score', 
                 fontsize=16, fontweight='bold')
        plt.xlabel('Threat Score', fontsize=12)
        plt.ylabel('IP Address', fontsize=12)
        plt.tight_layout()
        plt.savefig(self.output_dir / 'top_attackers.png', dpi=300)
        plt.close()

    def plot_threat_distribution(self, threats: list):
        """Plot distribution of threat types"""
        if not threats:
            return

        threat_types = []
        for threat in threats:
            for t in threat['threats']:
                threat_types.append(t['type'])

        if not threat_types:
            return

        threat_counts = Counter(threat_types)

        plt.figure(figsize=(10, 8))
        plt.pie(threat_counts.values(), labels=threat_counts.keys(), 
               autopct='%1.1f%%', startangle=90,
               colors=sns.color_palette('Set2', len(threat_counts)))
        plt.title('Threat Type Distribution', fontsize=16, fontweight='bold')
        plt.tight_layout()
        plt.savefig(self.output_dir / 'threat_distribution.png', dpi=300)
        plt.close()

    def plot_severity_distribution(self, scored_ips: list):
        """Plot distribution of severity levels"""
        if not scored_ips:
            return

        severities = [ip['severity'] for ip in scored_ips]
        severity_counts = Counter(severities)

        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
        labels = [s for s in severity_order if s in severity_counts]
        values = [severity_counts[s] for s in labels]
        colors = ['#e74c3c', '#f39c12', '#f1c40f', '#3498db', '#95a5a6']
        colors = colors[:len(labels)]

        plt.figure(figsize=(10, 6))
        bars = plt.bar(labels, values, color=colors, edgecolor='black')
        plt.title('Threat Severity Distribution', fontsize=16, fontweight='bold')
        plt.xlabel('Severity Level', fontsize=12)
        plt.ylabel('Number of IPs', fontsize=12)

        # Add value labels on bars
        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2., height,
                    f'{int(height)}',
                    ha='center', va='bottom', fontsize=10)

        plt.tight_layout()
        plt.savefig(self.output_dir / 'severity_distribution.png', dpi=300)
        plt.close()
