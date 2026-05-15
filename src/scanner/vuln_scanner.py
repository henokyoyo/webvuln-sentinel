"""
Vulnerability Scanner Module
Checks for common web vulnerabilities including SQLi, XSS, Directory Traversal, and more
"""

import requests
from urllib.parse import urljoin, urlparse, parse_qs
from rich.console import Console

console = Console()

class VulnScanner:
    def __init__(self, target_url, silent=False):
        self.target_url = target_url.rstrip('/')
        self.silent = silent
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'WebVuln-Sentinel/1.0'
        })
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.findings = []
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
    
    def check_security_headers(self):
        """Check for missing security headers"""
        self._print("\n[cyan][*] Checking security headers...[/cyan]")
        
        security_headers = {
            'X-Frame-Options': 'Clickjacking protection',
            'X-Content-Type-Options': 'MIME sniffing protection',
            'Content-Security-Policy': 'XSS/data injection protection',
            'Strict-Transport-Security': 'HTTPS enforcement',
            'X-XSS-Protection': 'XSS filter',
            'Referrer-Policy': 'Referrer information control',
            'Permissions-Policy': 'Browser feature control'
        }
        
        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)
            
            for header, description in security_headers.items():
                if header not in response.headers:
                    self.findings.append({
                        'type': 'Missing Security Header',
                        'severity': 'Medium',
                        'header': header,
                        'description': description,
                        'remediation': f'Add {header} header to your web server configuration'
                    })
                    self._print(f"  [yellow][-] Missing: {header} ({description})[/yellow]")
                else:
                    self._print(f"  [green][+] Present: {header}[/green]")
                    
        except requests.exceptions.RequestException as e:
            self._print(f"[red][!] Connection error: {e}[/red]")
        
        return self.findings
    
    def check_ssl_tls(self):
        """Check SSL/TLS certificate"""
        self._print("\n[cyan][*] Checking SSL/TLS...[/cyan]")
        
        if not self.target_url.startswith('https'):
            self.findings.append({
                'type': 'No HTTPS',
                'severity': 'High',
                'description': 'Site does not use HTTPS',
                'remediation': 'Install SSL certificate and enforce HTTPS'
            })
            self._print("  [red][!] Site is not using HTTPS[/red]")
            return self.findings
        
        try:
            import ssl
            import socket
            from datetime import datetime
            
            hostname = self.target_url.replace('https://', '').split('/')[0]
            ctx = ssl.create_default_context()
            
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    expiry = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_left = (expiry - datetime.now()).days
                    
                    if days_left < 0:
                        self.findings.append({
                            'type': 'SSL Certificate Expired',
                            'severity': 'Critical',
                            'description': f'SSL certificate expired on {expiry}',
                            'remediation': 'Renew SSL certificate immediately'
                        })
                        self._print(f"  [red][!] Certificate EXPIRED[/red]")
                    elif days_left < 30:
                        self._print(f"  [yellow][-] Certificate expires in {days_left} days[/yellow]")
                    else:
                        self._print(f"  [green][+] Certificate valid for {days_left} days[/green]")
                        
        except Exception as e:
            self._print(f"  [red][!] SSL check failed: {e}[/red]")
        
        return self.findings
    
    def check_sql_injection(self):
        """Test for SQL injection vulnerabilities"""
        self._print("\n[cyan][*] Testing for SQL Injection vulnerabilities...[/cyan]")
        
        sql_payloads = [
            "'",
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' #",
            "admin' --",
            "1' OR '1'='1",
        ]
        
        sql_errors = [
            "SQL syntax",
            "mysql_fetch",
            "ORA-",
            "PostgreSQL",
            "SQLite",
            "Microsoft SQL",
            "ODBC Driver",
            "syntax error",
            "unclosed quotation",
        ]
        
        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)
            parsed_url = urlparse(self.target_url)
            params = parse_qs(parsed_url.query)
            
            if params:
                self._print(f"  [dim]Found {len(params)} URL parameter(s)[/dim]")
                for param_name in params.keys():
                    for payload in sql_payloads[:3]:
                        test_params = params.copy()
                        test_params[param_name] = payload
                        
                        try:
                            test_url = parsed_url._replace(query='&'.join(
                                [f"{k}={v[0]}" for k, v in test_params.items()]
                            )).geturl()
                            
                            test_response = self.session.get(test_url, timeout=10, verify=False)
                            
                            for error in sql_errors:
                                if error.lower() in test_response.text.lower():
                                    self.findings.append({
                                        'type': 'SQL Injection (Error-Based)',
                                        'severity': 'Critical',
                                        'parameter': param_name,
                                        'payload': payload,
                                        'description': f'SQL error detected in parameter: {param_name}',
                                        'remediation': 'Use parameterized queries/prepared statements'
                                    })
                                    self._print(f"  [red][!] SQLi found in parameter: {param_name}[/red]")
                                    break
                        except:
                            pass
            
            if not params:
                self._print("  [dim]No URL parameters found to test[/dim]")
                
        except Exception as e:
            self._print(f"  [yellow][-] SQLi test skipped: {e}[/yellow]")
        
        return self.findings
    
    def check_xss(self):
        """Test for Cross-Site Scripting vulnerabilities"""
        self._print("\n[cyan][*] Testing for XSS vulnerabilities...[/cyan]")
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "'><script>alert('XSS')</script>",
        ]
        
        try:
            parsed_url = urlparse(self.target_url)
            params = parse_qs(parsed_url.query)
            
            if params:
                self._print(f"  [dim]Testing {len(params)} parameter(s) for XSS...[/dim]")
                for param_name in params.keys():
                    for payload in xss_payloads[:2]:
                        test_params = params.copy()
                        test_params[param_name] = payload
                        
                        try:
                            test_url = parsed_url._replace(query='&'.join(
                                [f"{k}={v[0]}" for k, v in test_params.items()]
                            )).geturl()
                            
                            response = self.session.get(test_url, timeout=10, verify=False)
                            
                            if payload in response.text:
                                self.findings.append({
                                    'type': 'Cross-Site Scripting (XSS)',
                                    'severity': 'High',
                                    'parameter': param_name,
                                    'payload': payload,
                                    'description': f'Reflected XSS in parameter: {param_name}',
                                    'remediation': 'Implement output encoding and Content-Security-Policy header'
                                })
                                self._print(f"  [red][!] Reflected XSS in parameter: {param_name}[/red]")
                                break
                        except:
                            pass
            
            if not params:
                self._print("  [dim]No URL parameters to test for XSS[/dim]")
                
        except Exception as e:
            self._print(f"  [yellow][-] XSS test skipped: {e}[/yellow]")
        
        return self.findings
    
    def check_directory_traversal(self):
        """Test for directory traversal vulnerabilities"""
        self._print("\n[cyan][*] Testing for Directory Traversal...[/cyan]")
        
        traversal_payloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\win.ini',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
        ]
        
        try:
            parsed_url = urlparse(self.target_url)
            params = parse_qs(parsed_url.query)
            
            common_params = ['file', 'page', 'path', 'doc', 'dir', 'include']
            
            if params:
                for param_name in params.keys():
                    for payload in traversal_payloads:
                        test_params = params.copy()
                        test_params[param_name] = payload
                        
                        try:
                            test_url = parsed_url._replace(query='&'.join(
                                [f"{k}={v[0]}" for k, v in test_params.items()]
                            )).geturl()
                            
                            response = self.session.get(test_url, timeout=10, verify=False)
                            
                            indicators = ['root:', '[extensions]', 'mysql_', '<?php']
                            for indicator in indicators:
                                if indicator in response.text:
                                    self.findings.append({
                                        'type': 'Directory Traversal',
                                        'severity': 'Critical',
                                        'parameter': param_name,
                                        'payload': payload,
                                        'description': f'Directory traversal detected in parameter: {param_name}',
                                        'remediation': 'Validate and sanitize file paths. Use whitelists.'
                                    })
                                    self._print(f"  [red][!] Directory traversal in: {param_name}[/red]")
                                    break
                        except:
                            pass
            else:
                self._print("  [dim]No file parameters found to test[/dim]")
                
        except Exception as e:
            self._print(f"  [yellow][-] Traversal test skipped: {e}[/yellow]")
        
        return self.findings
    
    def check_exposed_files(self):
        """Check for commonly exposed sensitive files"""
        self._print("\n[cyan][*] Checking for exposed sensitive files...[/cyan]")
        
        sensitive_files = [
            '.git/config',
            '.env',
            'backup.zip',
            'wp-config.php.bak',
            'phpinfo.php',
            'robots.txt',
            '.htaccess',
            'admin/',
            'backup/',
            'config.php.bak'
        ]
        
        for file_path in sensitive_files:
            url = urljoin(self.target_url + '/', file_path)
            try:
                response = self.session.get(url, timeout=5, verify=False)
                if response.status_code == 200:
                    self.findings.append({
                        'type': 'Exposed Sensitive File',
                        'severity': 'High',
                        'file': file_path,
                        'url': url,
                        'description': f'Sensitive file exposed: {file_path}',
                        'remediation': f'Remove or restrict access to {file_path}'
                    })
                    self._print(f"  [red][!] Exposed: {file_path}[/red]")
                else:
                    self._print(f"  [green][+] Not found: {file_path}[/green]")
            except:
                self._print(f"  [dim][-] Skipped: {file_path}[/dim]")
        
        return self.findings
    
    def display_findings(self):
        """Display all vulnerability findings"""
        if not self.findings:
            console.print("\n[green][+] No vulnerabilities detected![/green]")
            return self.findings
        
        from rich.table import Table
        
        console.print(f"\n[bold red][!] Found {len(self.findings)} issues[/bold red]\n")
        
        table = Table(title="[bold red]VULNERABILITIES FOUND[/bold red]", border_style="red")
        table.add_column("Severity", style="bold")
        table.add_column("Type", style="cyan")
        table.add_column("Description", style="white")
        table.add_column("Remediation", style="green")
        
        for finding in self.findings:
            severity_color = {
                'Critical': '[bold red]Critical[/bold red]',
                'High': '[red]High[/red]',
                'Medium': '[yellow]Medium[/yellow]',
                'Low': '[green]Low[/green]'
            }
            
            table.add_row(
                severity_color.get(finding['severity'], finding['severity']),
                finding['type'],
                finding.get('description', finding.get('header', '')),
                finding.get('remediation', '')
            )
        
        console.print(table)
        return self.findings