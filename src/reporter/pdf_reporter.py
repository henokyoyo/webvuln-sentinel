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
        self.findings = findings if findings else []
        self.port_results = port_results if port_results else []
        self.pdf = FPDF()
        self.pdf.set_auto_page_break(auto=True, margin=20)
        
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
        
        if self.port_results:
            self._add_port_scan_results()
            
        if self.findings:
            self._add_vulnerability_details()
            self._add_remediation_summary()
        else:
            self._add_no_findings()
            
        self._add_footer()
        
        # Save
        import os
        os.makedirs("reports", exist_ok=True)
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
        
        summary_text = (
            f'A security assessment was performed against {self.target_url} '
            f'on {datetime.now().strftime("%B %d, %Y")}. '
        )
        
        if self.findings:
            summary_text += (
                f'The assessment identified a total of {len(self.findings)} security finding(s). '
            )
        else:
            summary_text += 'No vulnerabilities were detected during the scan. '
            
        self.pdf.multi_cell(0, 6, summary_text)
        self.pdf.ln(5)
        
        self.pdf.set_font('Helvetica', 'B', 12)
        self.pdf.cell(0, 8, 'Finding Summary:', ln=True)
        self.pdf.set_font('Helvetica', '', 11)
        
        if any(severity_counts.values()):
            for severity, count in severity_counts.items():
                if count > 0:
                    self.pdf.cell(0, 6, f'  - {severity}: {count} finding(s)', ln=True)
        else:
            self.pdf.cell(0, 6, '  No vulnerabilities detected.', ln=True)
            
        # Add risk score if findings exist
        if self.findings:
            risk_score = self._calculate_risk()
            self.pdf.ln(5)
            self.pdf.set_font('Helvetica', 'B', 12)
            self.pdf.cell(0, 8, f'Overall Risk Score: {risk_score}/100', ln=True)
    
    def _calculate_risk(self):
        """Calculate risk score"""
        weights = {'Critical': 25, 'High': 15, 'Medium': 7, 'Low': 2}
        total = 0
        for finding in self.findings:
            sev = finding.get('severity', 'Low')
            total += weights.get(sev, 1)
        return min(total, 100)
    
    def _add_port_scan_results(self):
        """Add port scan results"""
        self.pdf.add_page()
        
        self.pdf.set_font('Helvetica', 'B', 18)
        self.pdf.cell(0, 12, '2. Port Scan Results', ln=True)
        self.pdf.ln(5)
        
        if not self.port_results:
            self.pdf.set_font('Helvetica', '', 11)
            self.pdf.cell(0, 8, 'No open ports found.', ln=True)
            return
        
        self.pdf.set_font('Helvetica', '', 11)
        self.pdf.cell(0, 6, f'Found {len(self.port_results)} open port(s):', ln=True)
        self.pdf.ln(3)
        
        # Table header
        self.pdf.set_font('Helvetica', 'B', 10)
        self.pdf.set_fill_color(50, 50, 50)
        self.pdf.set_text_color(255, 255, 255)
        
        col_widths = [25, 30, 55, 70]
        headers = ['Port', 'Protocol', 'Service', 'Product']
        
        for i, header in enumerate(headers):
            self.pdf.cell(col_widths[i], 8, header, border=1, fill=True)
        self.pdf.ln()
        
        # Table rows
        self.pdf.set_text_color(0, 0, 0)
        self.pdf.set_font('Helvetica', '', 9)
        
        for port in self.port_results:
            row_data = [
                str(port.get('port', '')),
                port.get('protocol', ''),
                port.get('service', ''),
                (port.get('product', '') or 'Unknown')[:30]
            ]
            
            # Check page break
            if self.pdf.get_y() > 260:
                self.pdf.add_page()
            
            for i, data in enumerate(row_data):
                self.pdf.cell(col_widths[i], 7, data, border=1)
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
            severity = finding.get('severity', 'Low')
            
            # Severity color
            if severity == 'Critical':
                self.pdf.set_text_color(200, 0, 0)
            elif severity == 'High':
                self.pdf.set_text_color(220, 80, 0)
            elif severity == 'Medium':
                self.pdf.set_text_color(200, 150, 0)
            else:
                self.pdf.set_text_color(0, 130, 0)
            
            # Finding header
            self.pdf.set_font('Helvetica', 'B', 11)
            finding_title = f'{i}. [{severity}] {finding.get("type", "Unknown")}'
            self.pdf.cell(0, 7, finding_title, ln=True)
            
            # Reset color
            self.pdf.set_text_color(0, 0, 0)
            self.pdf.set_font('Helvetica', '', 9)
            
            # Description
            desc = finding.get('description', 'No description')
            # Clean description - remove unicode chars that fpdf doesn't like
            desc = desc.replace('\u2713', '[+]').replace('\u2717', '[-]').replace('\u2013', '-')
            self.pdf.multi_cell(0, 5, f'Description: {desc}')
            self.pdf.ln(1)
            
            # Remediation
            rem = finding.get('remediation', 'No remediation available')
            rem = rem.replace('\u2713', '[+]').replace('\u2717', '[-]').replace('\u2013', '-')
            self.pdf.set_font('Helvetica', 'B', 9)
            self.pdf.cell(0, 5, 'Remediation:', ln=True)
            self.pdf.set_font('Helvetica', '', 9)
            self.pdf.multi_cell(0, 5, rem)
            
            self.pdf.ln(4)
    
    def _add_remediation_summary(self):
        """Add remediation summary"""
        self.pdf.add_page()
        
        self.pdf.set_font('Helvetica', 'B', 18)
        self.pdf.cell(0, 12, '4. Remediation Priority', ln=True)
        self.pdf.ln(5)
        
        self.pdf.set_font('Helvetica', '', 10)
        self.pdf.multi_cell(0, 5,
            'The following section provides a prioritized list of remediation '
            'actions to address identified vulnerabilities.\n'
        )
        
        # Group by severity
        priorities = {'Critical': [], 'High': [], 'Medium': [], 'Low': []}
        for finding in self.findings:
            sev = finding.get('severity', 'Low')
            rem = finding.get('remediation', '')
            rem = rem.replace('\u2713', '[+]').replace('\u2717', '[-]')
            if sev in priorities and rem not in priorities[sev]:
                priorities[sev].append(rem)
        
        counter = 1
        for severity, remediations in priorities.items():
            if remediations:
                self.pdf.set_font('Helvetica', 'B', 11)
                self.pdf.cell(0, 7, f'{severity} Priority:', ln=True)
                self.pdf.set_font('Helvetica', '', 9)
                for rem in remediations:
                    self.pdf.cell(0, 5, f'  {counter}. {rem}', ln=True)
                    counter += 1
                self.pdf.ln(3)
    
    def _add_no_findings(self):
        """Add a page when no findings exist"""
        self.pdf.add_page()
        self.pdf.set_font('Helvetica', 'B', 18)
        self.pdf.cell(0, 12, '3. Scan Results', ln=True)
        self.pdf.ln(10)
        self.pdf.set_font('Helvetica', '', 12)
        self.pdf.cell(0, 8, 'No vulnerabilities were detected during this scan.', ln=True, align='C')
        self.pdf.ln(5)
        self.pdf.set_font('Helvetica', 'I', 10)
        self.pdf.cell(0, 8, 'This is a positive result indicating good security posture.', ln=True, align='C')
    
    def _add_footer(self):
        """Add footer with disclaimer"""
        self.pdf.add_page()
        
        self.pdf.ln(60)
        self.pdf.set_font('Helvetica', 'B', 14)
        self.pdf.cell(0, 10, 'Disclaimer', ln=True, align='C')
        self.pdf.ln(10)
        
        self.pdf.set_font('Helvetica', '', 9)
        disclaimer = (
            'This report is provided for educational and authorized assessment '
            'purposes only. The findings contained within this report are based '
            'on automated scanning techniques and may include false positives. '
            'Manual verification of all findings is recommended before taking '
            'any remediation actions.\n\n'
            'This tool should only be used on systems you own or have explicit '
            'written permission to test. Unauthorized scanning of systems is '
            'illegal and unethical.'
        )
        self.pdf.multi_cell(0, 5, disclaimer)