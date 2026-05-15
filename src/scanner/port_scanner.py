"""
Port Scanner Module
Scans target for open ports and running services
"""

import nmap
from rich.console import Console
from rich.table import Table

console = Console()

class PortScanner:
    def __init__(self, target, silent=False):
        self.target = target
        self.silent = silent
        self.nm = nmap.PortScanner()
        self.results = []
        self.output_buffer = []
    
    def _print(self, message):
        """Print or buffer output based on silent mode"""
        if self.silent:
            self.output_buffer.append(message)
        else:
            console.print(message)
    
    def flush_buffer(self):
        """Print all buffered output"""
        for msg in self.output_buffer:
            console.print(msg)
        self.output_buffer = []
    
    def scan_common_ports(self):
        """Scan most common 1000 ports"""
        self._print(f"\n[cyan][*] Scanning common ports on {self.target}...[/cyan]")
        
        try:
            self.nm.scan(self.target, arguments='-T4 -F')
            
            if self.target not in self.nm.all_hosts():
                self._print("[red][!] Host seems down or unreachable[/red]")
                return []
            
            for proto in self.nm[self.target].all_protocols():
                ports = self.nm[self.target][proto].keys()
                for port in ports:
                    state = self.nm[self.target][proto][port]['state']
                    if state == 'open':
                        service = self.nm[self.target][proto][port]['name']
                        product = self.nm[self.target][proto][port].get('product', 'unknown')
                        version = self.nm[self.target][proto][port].get('version', '')
                        
                        self.results.append({
                            'port': port,
                            'protocol': proto,
                            'service': service,
                            'product': product,
                            'version': version,
                            'state': state
                        })
            
            return self.results
            
        except Exception as e:
            self._print(f"[red][!] Scan error: {e}[/red]")
            return []
    
    def scan_specific_ports(self, ports_list):
        """Scan specific ports"""
        ports_str = ','.join(map(str, ports_list))
        self._print(f"\n[cyan][*] Scanning ports: {ports_str} on {self.target}...[/cyan]")
        
        try:
            self.nm.scan(self.target, arguments=f'-T4 -p {ports_str}')
            
            if self.target not in self.nm.all_hosts():
                self._print("[red][!] Host seems down or unreachable[/red]")
                return []
            
            for proto in self.nm[self.target].all_protocols():
                ports = self.nm[self.target][proto].keys()
                for port in ports:
                    state = self.nm[self.target][proto][port]['state']
                    if state == 'open':
                        service = self.nm[self.target][proto][port]['name']
                        self.results.append({
                            'port': port,
                            'protocol': proto,
                            'service': service,
                            'state': state
                        })
            
            return self.results
            
        except Exception as e:
            self._print(f"[red][!] Scan error: {e}[/red]")
            return []
    
    def display_results(self):
        """Display scan results in a table"""
        if not self.results:
            console.print("[yellow][!] No open ports found[/yellow]")
            return self.results
        
        table = Table(title="[bold green]OPEN PORTS FOUND[/bold green]", border_style="green")
        table.add_column("Port", style="cyan")
        table.add_column("Protocol", style="yellow")
        table.add_column("Service", style="white")
        table.add_column("Product", style="magenta")
        table.add_column("Version", style="blue")
        
        for r in self.results:
            table.add_row(
                str(r['port']),
                r['protocol'],
                r['service'],
                r.get('product', '-'),
                r.get('version', '-')
            )
        
        console.print(table)
        return self.results