"""
WebVuln Sentinel - Web Vulnerability Scanner
A professional security assessment tool for OWASP Top 10 vulnerabilities
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import print as rprint
from src.scanner.port_scanner import PortScanner
from src.scanner.vuln_scanner import VulnScanner
from src.reporter.pdf_reporter import PDFReporter
from src.utils.cve_lookup import CVELookup
from src.utils.risk_calculator import RiskCalculator

console = Console()

def show_banner():
    banner = """
╦ ╦╔═╗╔╗ ╦  ╦ ╦╦  ╔╗╔  ╔═╗╔═╗╔╗╔╔╦╗╦╔╗╔╔═╗╦  
║║║║╣ ╠╩╗╚╗╔╝║  ║║║  ╚═╗║╣ ║║║ ║ ║║║║║╣ ║  
╚╩╝╚═╝╚═╝ ╚╝ ╩═╝╝╚╝  ╚═╝╚═╝╝╚╝ ╩ ╩╝╚╝╚═╝╩═╝
    """
    console.print(Panel.fit(banner, border_style="cyan"))
    console.print("[bold green]A Professional Vulnerability Assessment Toolkit[/bold green]\n")

def show_main_menu():
    table = Table(title="[bold cyan]MAIN MENU[/bold cyan]", show_header=False, border_style="cyan")
    table.add_column("Option", style="yellow")
    table.add_column("Description", style="white")
    
    table.add_row("[1]", "Quick Scan - Ports + Basic Vulnerabilities")
    table.add_row("[2]", "Deep Scan - Comprehensive Assessment")
    table.add_row("[3]", "Custom Scan - Choose specific tests")
    table.add_row("[4]", "View Previous Reports")
    table.add_row("[5]", "About & Help")
    table.add_row("[0]", "Exit")
    
    console.print(table)

def get_target():
    """Get target URL from user"""
    target = console.input("\n[bold cyan]Enter target URL (e.g., http://example.com): [/bold cyan]")
    return target.strip()

def view_reports():
    """View previously generated PDF reports"""
    from datetime import datetime
    
    reports_dir = "reports"
    os.makedirs(reports_dir, exist_ok=True)
    
    pdf_files = [f for f in os.listdir(reports_dir) if f.endswith('.pdf')]
    
    if not pdf_files:
        console.print("\n[blue][i] No reports found yet. Run a scan to generate one![/blue]")
        return
    
    console.print(f"\n[bold green]Found {len(pdf_files)} report(s):[/bold green]\n")
    
    table = Table(title="[bold cyan]PREVIOUS REPORTS[/bold cyan]", border_style="cyan")
    table.add_column("#", style="dim")
    table.add_column("Filename", style="white")
    table.add_column("Size", style="yellow")
    table.add_column("Date", style="green")
    
    for i, pdf_file in enumerate(pdf_files, 1):
        filepath = os.path.join(reports_dir, pdf_file)
        size_kb = os.path.getsize(filepath) / 1024
        mod_time = datetime.fromtimestamp(os.path.getmtime(filepath))
        date_str = mod_time.strftime("%Y-%m-%d %H:%M")
        
        table.add_row(
            str(i),
            pdf_file,
            f"{size_kb:.1f} KB",
            date_str
        )
    
    console.print(table)
    
    open_choice = console.input(f"\n[bold cyan]Open a report? Enter number (1-{len(pdf_files)}) or press Enter to skip: [/bold cyan]")
    
    if open_choice.isdigit() and 1 <= int(open_choice) <= len(pdf_files):
        selected = pdf_files[int(open_choice) - 1]
        filepath = os.path.join(reports_dir, selected)
        os.startfile(filepath)
        console.print(f"[green][+] Opened: {selected}[/green]")

def quick_scan():
    """Perform a quick scan"""
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    
    target = get_target()
    hostname = target.replace('https://', '').replace('http://', '').split('/')[0]
    
    console.print(f"\n[bold]Starting Quick Scan on {target}...[/bold]\n")
    
    port_scanner = PortScanner(hostname, silent=True)
    vuln_scanner = VulnScanner(target, silent=True)
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console
    ) as progress:
        
        task1 = progress.add_task("[cyan]Phase 1: Port Scanning", total=100)
        port_scanner.scan_common_ports()
        progress.update(task1, visible=False)
        
        task2 = progress.add_task("[cyan]Phase 2: Vulnerability Check", total=100)
        vuln_scanner.check_security_headers()
        progress.update(task2, completed=15)
        vuln_scanner.check_ssl_tls()
        progress.update(task2, completed=30)
        vuln_scanner.check_exposed_files()
        progress.update(task2, completed=50)
        vuln_scanner.check_sql_injection()
        progress.update(task2, completed=75)
        vuln_scanner.check_xss()
        progress.update(task2, visible=False)
        
        findings = vuln_scanner.findings
        port_results = port_scanner.results
    
    # Flush buffered output
    port_scanner.flush_buffer()
    vuln_scanner.flush_buffer()
    
    # Show detailed results
    console.print("\n[bold cyan]DETAILED RESULTS:[/bold cyan]")
    port_scanner.display_results()
    vuln_scanner.display_findings()
    
    # Show Risk Dashboard
    risk_calc = RiskCalculator()
    risk_calc.display_dashboard(findings, target, "Quick Scan")
    
    console.print("\n[bold green][✓] Quick Scan Complete![/bold green]")
    
    generate = console.input("\n[bold cyan]Generate PDF report? (y/n): [/bold cyan]")
    if generate.lower() == 'y':
        reporter = PDFReporter(target, findings if findings else [], port_results if port_results else [])
        reporter.generate()
    
    console.input("\n[dim]Press Enter to continue...[/dim]")

def deep_scan():
    """Perform a comprehensive deep scan"""
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    
    target = get_target()
    hostname = target.replace('https://', '').replace('http://', '').split('/')[0]
    
    console.print(f"\n[bold red]Starting DEEP Scan on {target}...[/bold red]")
    
    port_scanner = PortScanner(hostname, silent=True)
    vuln_scanner = VulnScanner(target, silent=True)
    cve_lookup = CVELookup(silent=True)
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console
    ) as progress:
        
        task = progress.add_task("[red]Deep Scan Progress", total=100)
        
        port_scanner.scan_common_ports()
        progress.update(task, completed=15)
        
        vuln_scanner.check_security_headers()
        progress.update(task, completed=25)
        
        vuln_scanner.check_ssl_tls()
        progress.update(task, completed=35)
        
        vuln_scanner.check_exposed_files()
        progress.update(task, completed=50)
        
        vuln_scanner.check_sql_injection()
        progress.update(task, completed=65)
        
        vuln_scanner.check_xss()
        progress.update(task, completed=80)
        
        vuln_scanner.check_directory_traversal()
        progress.update(task, completed=85)
        
        cve_lookup.lookup_port_results(port_scanner.results)
        progress.update(task, completed=95)
        
        progress.update(task, visible=False)
        
        findings = vuln_scanner.findings
        port_results = port_scanner.results
    
    # Flush buffered output
    port_scanner.flush_buffer()
    vuln_scanner.flush_buffer()
    cve_lookup.flush_buffer()
    
    # Show detailed results
    console.print("\n[bold cyan]DETAILED RESULTS:[/bold cyan]")
    port_scanner.display_results()
    vuln_scanner.display_findings()
    cve_lookup.display_cve_results()
    
    # Show Risk Dashboard
    risk_calc = RiskCalculator()
    risk_calc.display_dashboard(findings, target, "Deep Scan")
    
    console.print("\n[bold green][✓] Deep Scan Complete![/bold green]")
    
    generate = console.input("\n[bold cyan]Generate PDF report? (y/n): [/bold cyan]")
    if generate.lower() == 'y':
        reporter = PDFReporter(target, findings if findings else [], port_results if port_results else [])
        reporter.generate()
    
    console.input("\n[dim]Press Enter to continue...[/dim]")

def custom_scan():
    """Custom scan - user selects which modules to run"""
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    
    target = get_target()
    hostname = target.replace('https://', '').replace('http://', '').split('/')[0]
    
    # Module selection menu
    console.print("\n[bold cyan]Select modules to run (Y/n or y/N):[/bold cyan]\n")
    
    modules = [
        ("Port Scanning", True),
        ("Security Headers", True),
        ("SSL/TLS Check", True),
        ("Exposed Files", True),
        ("SQL Injection", True),
        ("XSS Testing", True),
        ("Directory Traversal", True),
        ("CVE Lookup", False),
    ]
    
    selected = []
    for i, (name, default) in enumerate(modules, 1):
        prompt = "Y/n" if default else "y/N"
        choice = console.input(f"  [{i}] {name} [dim]({prompt})[/dim]: ").strip().lower()
        
        if default:
            if choice != 'n':
                selected.append(name)
        else:
            if choice == 'y':
                selected.append(name)
    
    if not selected:
        console.print("\n[red][!] No modules selected. Aborting.[/red]")
        return
    
    console.print(f"\n[bold]Running Custom Scan with {len(selected)} module(s)...[/bold]\n")
    
    port_results = []
    findings = []
    
    port_scanner = PortScanner(hostname, silent=True)
    vuln_scanner = VulnScanner(target, silent=True)
    cve_lookup = CVELookup(silent=True)
    
    total_steps = len(selected)
    step_size = 100 / total_steps
    current_step = 0
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console
    ) as progress:
        
        task = progress.add_task("[cyan]Custom Scan", total=100)
        
        if "Port Scanning" in selected:
            progress.update(task, description="[cyan]Port Scanning...")
            port_scanner.scan_common_ports()
            current_step += 1
            progress.update(task, completed=current_step * step_size)
        
        if "Security Headers" in selected:
            progress.update(task, description="[cyan]Security Headers...")
            vuln_scanner.check_security_headers()
            current_step += 1
            progress.update(task, completed=current_step * step_size)
        
        if "SSL/TLS Check" in selected:
            progress.update(task, description="[cyan]SSL/TLS Check...")
            vuln_scanner.check_ssl_tls()
            current_step += 1
            progress.update(task, completed=current_step * step_size)
        
        if "Exposed Files" in selected:
            progress.update(task, description="[cyan]Exposed Files...")
            vuln_scanner.check_exposed_files()
            current_step += 1
            progress.update(task, completed=current_step * step_size)
        
        if "SQL Injection" in selected:
            progress.update(task, description="[cyan]SQL Injection...")
            vuln_scanner.check_sql_injection()
            current_step += 1
            progress.update(task, completed=current_step * step_size)
        
        if "XSS Testing" in selected:
            progress.update(task, description="[cyan]XSS Testing...")
            vuln_scanner.check_xss()
            current_step += 1
            progress.update(task, completed=current_step * step_size)
        
        if "Directory Traversal" in selected:
            progress.update(task, description="[cyan]Directory Traversal...")
            vuln_scanner.check_directory_traversal()
            current_step += 1
            progress.update(task, completed=current_step * step_size)
        
        if "CVE Lookup" in selected:
            progress.update(task, description="[cyan]CVE Lookup...")
            cve_lookup.lookup_port_results(port_scanner.results)
            current_step += 1
            progress.update(task, completed=current_step * step_size)
        
        progress.update(task, visible=False)
        findings = vuln_scanner.findings
        port_results = port_scanner.results
    
    # Flush output
    port_scanner.flush_buffer()
    vuln_scanner.flush_buffer()
    cve_lookup.flush_buffer()
    
    # Show results
    console.print(f"\n[bold cyan]CUSTOM SCAN RESULTS ({len(selected)} modules):[/bold cyan]")
    
    if "Port Scanning" in selected:
        port_scanner.display_results()
    
    vuln_scanner.display_findings()
    
    if "CVE Lookup" in selected:
        cve_lookup.display_cve_results()
    
    # Risk Dashboard
    risk_calc = RiskCalculator()
    risk_calc.display_dashboard(findings, target, "Custom Scan")
    
    console.print("\n[bold green][✓] Custom Scan Complete![/bold green]")
    
    generate = console.input("\n[bold cyan]Generate PDF report? (y/n): [/bold cyan]")
    if generate.lower() == 'y':
        reporter = PDFReporter(target, findings if findings else [], port_results if port_results else [])
        reporter.generate()
    
    console.input("\n[dim]Press Enter to continue...[/dim]")

def main():
    show_banner()
    
    while True:
        show_main_menu()
        choice = console.input("\n[bold yellow]Select an option > [/bold yellow]")
        
        if choice == "1":
            quick_scan()
        elif choice == "2":
            deep_scan()
        elif choice == "3":
            custom_scan()
        elif choice == "4":
            view_reports()
        elif choice == "5":
            console.print(Panel.fit(
                "[cyan]WebVuln Sentinel v1.0[/cyan]\n\n"
                "A professional web vulnerability scanner\n"
                "Built for cybersecurity educational purposes\n\n"
                "[dim]Part of bootcamp final project[/dim]",
                border_style="cyan"
            ))
        elif choice == "0":
            console.print("\n[red][-] Exiting...[/red]")
            sys.exit(0)
        else:
            console.print("\n[red][!] Invalid option. Try again.[/red]")

if __name__ == "__main__":
    main()