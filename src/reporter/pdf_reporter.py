"""
PDF Report Generator Module
Generates professional vulnerability assessment reports
"""

from fpdf import FPDF
from datetime import datetime
from rich.console import Console

console = Console()

class PDFReporter:
    def __init__(self, target_url, findings, port_results=None):
        self.target_url = target_url
        self.findings = findings
        self.port_results = port_results or []
        self.pdf = FPDF()
        self.pdf.set_auto_page_break(auto=True, margin=15)
        
    def generate(self, filename=None):
        """Generate the PDF report"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"reports/scan_report_{timestamp}.pdf"
        
        console.print(f"\n[cyan][*] Generating PDF report...[/cyan]")
        
        # Metadata
        self.pdf.set_title(f'WebVuln Sentinel Report - {self.target_url}')
        self.pdf.set_author('WebVuln Sentinel')
        
        # Add pages
        self._add_cover_page()
        self._add_executive_summary()
        self._add_port_scan_results()
        self._add_vulnerability_details()
        self._add_remediation_summary()
        self._add_footer()
        
        # Save
        self.pdf.output(filename)
        console.print(f"[green][+] Report saved: {filename}[/green]")
        return filename
    
    def _add_cover_page(self):
        """Add cover page"""
        self.pdf.add_page()
        
        # Title
        self.pdf.set_font('Helvetica', 'B', 28)
        self.pdf.ln(50)
        self.pdf.cell(0, 15, 'WebVuln Sentinel', ln=True, align='C')
        
        self.pdf.set_font('Helvetica', '', 16)
        self.pdf.cell(0, 10, 'Vulnerability Assessment Report', ln=True, align='C')
        
        self.pdf.ln(20)
        self.pdf.set_font('Helvetica', '', 12)
        self.pdf.cell(0, 8, f'Target: {self.target_url}', ln=True, align='C')
        self.pdf.cell(0, 8, f'Date: {datetime.now().strftime("%B %d, %Y")}', ln=True, align='C')
        self.pdf.cell(0, 8, f'Time: {datetime.now().strftime("%H:%M:%S")}', ln=True, align='C')
        
        self.pdf.ln(30)
        self.pdf.set_font('Helvetica', 'I', 10)
        self.pdf.cell(0, 8, 'Confidential - For Authorized Use Only', ln=True, align='C')
    
    def _add_executive_summary(self):
        """Add executive summary page"""
        self.pdf.add_page()
        
        self.pdf.set_font('Helvetica', 'B', 18)
        self.pdf.cell(0, 12, '1. Executive Summary', ln=True)
        self.pdf.ln(5)
        
        # Severity counts
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for finding in self.findings:
            sev = finding.get('severity', 'Low')
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        self.pdf.set_font('Helvetica', '', 11)
        self.pdf.multi_cell(0, 6, 
            f'A security assessment was performed against {self.target_url} '
            f'on {datetime.now().strftime("%B %d, %Y")}. '
            f'The assessment identified a total of {len(self.findings)} security findings.\n'
        )
        
        self.pdf.set_font('Helvetica', 'B', 12)
        self.pdf.cell(0, 8, 'Finding Summary:', ln=True)
        self.pdf.set_font('Helvetica', '', 11)
        
        for severity, count in severity_counts.items():
            if count > 0:
                self.pdf.cell(0, 6, f'  - {severity}: {count} finding(s)', ln=True)
        
        if len(self.findings) == 0:
            self.pdf.cell(0, 6, '  No vulnerabilities detected.', ln=True)
    
    def _add_port_scan_results(self):
        """Add port scan results"""
        self.pdf.add_page()
        
        self.pdf.set_font('Helvetica', 'B', 18)
        self.pdf.cell(0, 12, '2. Port Scan Results', ln=True)
        self.pdf.ln(5)
        
        if not self.port_results:
            self.pdf.set_font('Helvetica', '', 11)
            self.pdf.cell(0, 8, 'No open ports found or port scan was not performed.', ln=True)
            return
        
        self.pdf.set_font('Helvetica', '', 11)
        self.pdf.cell(0, 6, f'Found {len(self.port_results)} open port(s):', ln=True)
        self.pdf.ln(3)
        
        # Table header
        self.pdf.set_font('Helvetica', 'B', 10)
        self.pdf.set_fill_color(50, 50, 50)
        self.pdf.set_text_color(255, 255, 255)
        self.pdf.cell(25, 8, 'Port', border=1, fill=True)
        self.pdf.cell(25, 8, 'Protocol', border=1, fill=True)
        self.pdf.cell(50, 8, 'Service', border=1, fill=True)
        self.pdf.cell(60, 8, 'Product', border=1, fill=True)
        self.pdf.ln()
        
        # Table rows
        self.pdf.set_text_color(0, 0, 0)
        self.pdf.set_font('Helvetica', '', 10)
        for port in self.port_results:
            self.pdf.cell(25, 7, str(port.get('port', '')), border=1)
            self.pdf.cell(25, 7, port.get('protocol', ''), border=1)
            self.pdf.cell(50, 7, port.get('service', ''), border=1)
            self.pdf.cell(60, 7, port.get('product', '')[:25], border=1)
            self.pdf.ln()
    
    def _add_vulnerability_details(self):
        """Add detailed vulnerability findings"""
        self.pdf.add_page()
        
        self.pdf.set_font('Helvetica', 'B', 18)
        self.pdf.cell(0, 12, '3. Vulnerability Details', ln=True)
        self.pdf.ln(5)
        
        if not self.findings:
            self.pdf.set_font('Helvetica', '', 11)
            self.pdf.cell(0, 8, 'No vulnerabilities detected.', ln=True)
            return
        
        for i, finding in enumerate(self.findings, 1):
            # Check if we need a new page
            if self.pdf.get_y() > 240:
                self.pdf.add_page()
            
            # Severity color
            severity = finding.get('severity', 'Low')
            if severity == 'Critical':
                self.pdf.set_text_color(255, 0, 0)
            elif severity == 'High':
                self.pdf.set_text_color(255, 100, 0)
            elif severity == 'Medium':
                self.pdf.set_text_color(255, 180, 0)
            else:
                self.pdf.set_text_color(0, 150, 0)
            
            # Finding header
            self.pdf.set_font('Helvetica', 'B', 12)
            self.pdf.cell(0, 8, f'{i}. [{severity}] {finding.get("type", "Unknown")}', ln=True)
            
            # Reset color
            self.pdf.set_text_color(0, 0, 0)
            self.pdf.set_font('Helvetica', '', 10)
            
            # Description
            desc = finding.get('description', 'No description available')
            self.pdf.multi_cell(0, 5, f'Description: {desc}')
            
            # Remediation
            rem = finding.get('remediation', 'No remediation available')
            self.pdf.set_font('Helvetica', 'B', 10)
            self.pdf.cell(0, 5, 'Remediation:', ln=True)
            self.pdf.set_font('Helvetica', '', 10)
            self.pdf.multi_cell(0, 5, f'{rem}')
            
            self.pdf.ln(3)
    
    def _add_remediation_summary(self):
        """Add remediation summary"""
        self.pdf.add_page()
        
        self.pdf.set_font('Helvetica', 'B', 18)
        self.pdf.cell(0, 12, '4. Remediation Summary', ln=True)
        self.pdf.ln(5)
        
        self.pdf.set_font('Helvetica', '', 11)
        self.pdf.multi_cell(0, 6,
            'The following section provides a prioritized list of remediation '
            'actions to address the identified vulnerabilities. Remediations '
            'are ordered by severity.\n'
        )
        
        # Group by severity
        priorities = {'Critical': [], 'High': [], 'Medium': [], 'Low': []}
        for finding in self.findings:
            sev = finding.get('severity', 'Low')
            if sev in priorities:
                priorities[sev].append(finding.get('remediation', ''))
        
        for severity, remediations in priorities.items():
            if remediations:
                self.pdf.set_font('Helvetica', 'B', 12)
                self.pdf.cell(0, 8, f'{severity} Priority:', ln=True)
                self.pdf.set_font('Helvetica', '', 10)
                for j, rem in enumerate(set(remediations), 1):
                    self.pdf.cell(0, 6, f'  {j}. {rem}', ln=True)
                self.pdf.ln(3)
    
    def _add_footer(self):
        """Add footer with disclaimer"""
        self.pdf.add_page()
        
        self.pdf.ln(80)
        self.pdf.set_font('Helvetica', 'B', 14)
        self.pdf.cell(0, 10, 'Disclaimer', ln=True, align='C')
        self.pdf.ln(5)
        
        self.pdf.set_font('Helvetica', '', 9)
        self.pdf.multi_cell(0, 5,
            'This report is provided for educational and authorized assessment '
            'purposes only. The findings contained within this report are based '
            'on automated scanning techniques and may include false positives. '
            'Manual verification of all findings is recommended before taking '
            'any remediation actions.\n\n'
            'This tool should only be used on systems you own or have explicit '
            'written permission to test. Unauthorized scanning of systems is '
            'illegal and unethical.'
        )