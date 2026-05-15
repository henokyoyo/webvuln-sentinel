"""
Risk Score Calculator Module
Calculates overall risk score based on findings severity
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.layout import Layout

console = Console()

class RiskCalculator:
    def __init__(self):
        self.severity_weights = {
            'Critical': 10,
            'High': 7,
            'Medium': 4,
            'Low': 1
        }
        self.max_score = 100
    
    def calculate(self, findings):
        """Calculate risk score from findings"""
        if not findings:
            return {
                'score': 0,
                'level': 'None',
                'color': 'green',
                'emoji': '🟢',
                'counts': {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0},
                'total': 0
            }
        
        # Count by severity
        counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for finding in findings:
            severity = finding.get('severity', 'Low')
            if severity in counts:
                counts[severity] += 1
        
        # Calculate weighted score (capped at 100)
        raw_score = 0
        for severity, count in counts.items():
            raw_score += count * self.severity_weights[severity]
        
        score = min(raw_score, self.max_score)
        
        # Determine risk level
        if score >= 80:
            level = 'CRITICAL'
            color = 'red'
            emoji = '🔴'
        elif score >= 50:
            level = 'HIGH'
            color = 'red'
            emoji = '🟠'
        elif score >= 25:
            level = 'MEDIUM'
            color = 'yellow'
            emoji = '🟡'
        elif score > 0:
            level = 'LOW'
            color = 'green'
            emoji = '🟢'
        else:
            level = 'NONE'
            color = 'green'
            emoji = '✅'
        
        return {
            'score': score,
            'level': level,
            'color': color,
            'emoji': emoji,
            'counts': counts,
            'total': len(findings)
        }
    
    def display_dashboard(self, findings, target_url, scan_type="Quick Scan"):
        """Display the risk dashboard"""
        risk = self.calculate(findings)
        
        # Color mapping
        color_map = {
            'red': 'red',
            'yellow': 'yellow', 
            'green': 'green'
        }
        risk_color = color_map.get(risk['color'], 'green')
        
        # Build the dashboard
        console.print("\n")
        console.print(Panel.fit(
            f"[bold white]{risk['emoji']} OVERALL RISK: [bold {risk_color}]{risk['level']}[/bold {risk_color}] "
            f"({risk['score']}/100)[/bold white]",
            border_style=risk_color,
            title="[bold]RISK ASSESSMENT DASHBOARD[/bold]",
            subtitle=f"Target: {target_url} | Scan: {scan_type}"
        ))
        
        # Summary table
        table = Table(title="[bold]Finding Summary[/bold]", border_style=risk_color)
        table.add_column("Severity", style="bold")
        table.add_column("Count", style="bold")
        table.add_column("Weight", style="dim")
        table.add_column("Impact", style="bold")
        
        severity_order = ['Critical', 'High', 'Medium', 'Low']
        severity_styles = {
            'Critical': 'bold red',
            'High': 'red',
            'Medium': 'yellow',
            'Low': 'green'
        }
        
        for severity in severity_order:
            count = risk['counts'][severity]
            if count > 0:
                weight = count * self.severity_weights[severity]
                bar = '█' * min(count, 20)
                table.add_row(
                    f"[{severity_styles[severity]}]{severity}[/{severity_styles[severity]}]",
                    str(count),
                    str(weight),
                    bar
                )
        
        console.print(table)
        
        # Top recommendations
        if findings:
            console.print("\n[bold]🔧 TOP REMEDIATIONS:[/bold]")
            unique_remediations = []
            seen = set()
            for f in findings:
                rem = f.get('remediation', '')
                if rem and rem not in seen:
                    unique_remediations.append(rem)
                    seen.add(rem)
            
            for i, rem in enumerate(unique_remediations[:5], 1):
                console.print(f"  [cyan]{i}.[/cyan] {rem}")
        
        return risk

    def compare_scans(self, previous_risk, current_risk):
        """Compare two scan results"""
        if previous_risk is None:
            console.print("[dim]No previous scan to compare[/dim]")
            return
        
        diff = current_risk['score'] - previous_risk['score']
        
        if diff > 0:
            console.print(f"\n[red]📈 Risk INCREASED by {diff} points since last scan[/red]")
        elif diff < 0:
            console.print(f"\n[green]📉 Risk DECREASED by {abs(diff)} points since last scan[/green]")
        else:
            console.print(f"\n[yellow]➡️  Risk UNCHANGED since last scan[/yellow]")