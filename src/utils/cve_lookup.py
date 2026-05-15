"""
CVE Lookup Module
Queries the NVD (National Vulnerability Database) API for known vulnerabilities
based on detected services and versions.
"""

import requests
import time
from rich.console import Console
from rich.table import Table

console = Console()

class CVELookup:
    def __init__(self, silent=False):
        self.silent = silent
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.output_buffer = []
        self.cve_results = []
    
    def _print(self, message):
        if self.silent:
            self.output_buffer.append(message)
        else:
            console.print(message)
    
    def flush_buffer(self):
        for msg in self.output_buffer:
            console.print(msg)
        self.output_buffer = []
    
    def search_by_keyword(self, keyword, max_results=5):
        """Search CVEs by keyword (service name, version, etc.)"""
        params = {
            'keywordSearch': keyword,
            'resultsPerPage': max_results
        }
        
        try:
            response = requests.get(self.base_url, params=params, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get('vulnerabilities', [])
                
                for vuln in vulnerabilities:
                    cve = vuln.get('cve', {})
                    cve_id = cve.get('id', 'Unknown')
                    
                    # Get description
                    descriptions = cve.get('descriptions', [])
                    desc_text = 'No description'
                    for desc in descriptions:
                        if desc.get('lang') == 'en':
                            desc_text = desc.get('value', 'No description')
                            break
                    
                    # Get CVSS score
                    metrics = cve.get('metrics', {})
                    cvss_score = None
                    severity = 'UNKNOWN'
                    
                    # Try CVSS v3 first
                    cvss_v3 = metrics.get('cvssMetricV31', []) or metrics.get('cvssMetricV30', [])
                    if cvss_v3:
                        cvss_data = cvss_v3[0].get('cvssData', {})
                        cvss_score = cvss_data.get('baseScore')
                        severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                    else:
                        # Try CVSS v2
                        cvss_v2 = metrics.get('cvssMetricV2', [])
                        if cvss_v2:
                            cvss_data = cvss_v2[0].get('cvssData', {})
                            cvss_score = cvss_data.get('baseScore')
                            severity = cvss_v2[0].get('baseSeverity', 'UNKNOWN')
                    
                    self.cve_results.append({
                        'cve_id': cve_id,
                        'description': desc_text[:200] + '...' if len(desc_text) > 200 else desc_text,
                        'cvss_score': cvss_score,
                        'severity': severity,
                        'keyword': keyword
                    })
                
                return self.cve_results
                
            elif response.status_code == 403:
                self._print("[yellow][!] CVE API rate limited. Waiting...[/yellow]")
                time.sleep(5)
                return self.cve_results
            else:
                self._print(f"[yellow][!] CVE API error: {response.status_code}[/yellow]")
                return self.cve_results
                
        except Exception as e:
            self._print(f"[yellow][!] CVE lookup failed: {e}[/yellow]")
            return self.cve_results
    
    def search_by_service(self, service, version=None):
        """Search CVEs for a specific service and version"""
        query = service
        if version:
            query += f" {version}"
        
        self._print(f"  [dim]Looking up CVEs for: {query}...[/dim]")
        return self.search_by_keyword(query)
    
    def lookup_port_results(self, port_results):
        """Lookup CVEs for all detected services from port scan"""
        self._print("\n[cyan][*] Performing CVE lookup on detected services...[/cyan]")
        
        for result in port_results:
            service = result.get('service', '')
            product = result.get('product', '')
            version = result.get('version', '')
            
            if service and service != 'unknown':
                if product and product != 'unknown':
                    keyword = f"{product} {version}".strip()
                else:
                    keyword = service
                
                self.search_by_keyword(keyword, max_results=3)
                time.sleep(0.5)  # Rate limiting
            else:
                self._print(f"  [dim]Skipping unknown service on port {result.get('port')}[/dim]")
        
        return self.cve_results
    
    def display_cve_results(self):
        """Display CVE results in a table"""
        if not self.cve_results:
            console.print("[yellow][!] No CVE results found[/yellow]")
            return self.cve_results
        
        table = Table(title="[bold red]KNOWN VULNERABILITIES (CVE)[/bold red]", border_style="red")
        table.add_column("CVE ID", style="bold red")
        table.add_column("Severity", style="bold")
        table.add_column("CVSS", style="yellow")
        table.add_column("Description", style="white")
        table.add_column("Service", style="cyan")
        
        for cve in self.cve_results:
            severity_color = {
                'CRITICAL': '[bold red]CRITICAL[/bold red]',
                'HIGH': '[red]HIGH[/red]',
                'MEDIUM': '[yellow]MEDIUM[/yellow]',
                'LOW': '[green]LOW[/green]',
                'UNKNOWN': '[dim]UNKNOWN[/dim]'
            }
            
            cvss_str = f"{cve['cvss_score']:.1f}" if cve['cvss_score'] else 'N/A'
            
            table.add_row(
                cve['cve_id'],
                severity_color.get(cve['severity'], cve['severity']),
                cvss_str,
                cve['description'][:100],
                cve['keyword']
            )
        
        console.print(table)
        return self.cve_results