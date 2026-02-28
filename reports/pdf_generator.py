# reports/pdf_generator.py

import os
from datetime import datetime
from fpdf import FPDF


class EASMReport(FPDF):
    """Custom PDF class for EASM reports."""

    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=15)

    def header(self):
        self.set_font("Helvetica", "B", 12)
        self.cell(0, 10, "EASM Security Report", align="C", ln=True)
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.cell(0, 10, f"Page {self.page_no()}", align="C")

    def chapter_title(self, title):
        self.set_font("Helvetica", "B", 14)
        self.set_fill_color(52, 73, 94)
        self.set_text_color(255, 255, 255)
        self.cell(0, 10, title, ln=True, fill=True)
        self.set_text_color(0, 0, 0)
        self.ln(5)

    def section_title(self, title):
        self.set_font("Helvetica", "B", 11)
        self.set_text_color(52, 73, 94)
        self.cell(0, 8, title, ln=True)
        self.set_text_color(0, 0, 0)

    def body_text(self, text):
        self.set_font("Helvetica", "", 10)
        self.multi_cell(0, 6, str(text))
        self.ln(3)

    def add_table(self, headers, data, col_widths=None):
        """Add a simple table."""
        self.set_font("Helvetica", "B", 9)
        self.set_fill_color(240, 240, 240)

        if col_widths is None:
            col_widths = [190 // len(headers)] * len(headers)

        for i, header in enumerate(headers):
            self.cell(col_widths[i], 8, str(header), border=1, fill=True)
        self.ln()

        self.set_font("Helvetica", "", 8)
        for row in data[:50]:
            for i, cell in enumerate(row):
                text = str(cell)[:30]
                self.cell(col_widths[i], 7, text, border=1)
            self.ln()


def generate_pdf(report_data):
    """Generate a PDF report from report data."""
    domain = report_data.get("meta", {}).get("domain", "unknown")
    safe_domain = domain.replace(".", "_")

    os.makedirs("generated_reports", exist_ok=True)

    pdf = EASMReport()
    pdf.add_page()

    # Cover Page
    pdf.set_font("Helvetica", "B", 24)
    pdf.ln(30)
    pdf.cell(0, 15, "EASM Security Assessment", align="C", ln=True)
    pdf.ln(10)

    pdf.set_font("Helvetica", "B", 18)
    pdf.set_text_color(52, 73, 94)
    pdf.cell(0, 12, domain, align="C", ln=True)
    pdf.set_text_color(0, 0, 0)

    pdf.ln(20)
    pdf.set_font("Helvetica", "", 12)
    generated = report_data.get("meta", {}).get("generated_at", "")[:19]
    pdf.cell(0, 8, f"Generated: {generated}", align="C", ln=True)
    pdf.cell(0, 8, "Tool: EASM Tool v1.0.0", align="C", ln=True)

    risk_score = report_data.get("summary", {}).get("risk_score", 0)
    pdf.ln(20)
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, f"Risk Score: {risk_score}/100", align="C", ln=True)

    # Executive Summary
    pdf.add_page()
    pdf.chapter_title("Executive Summary")

    summary = report_data.get("summary", {})
    vuln_breakdown = report_data.get("vuln_breakdown", {})

    pdf.body_text(f"""
This report presents findings from an EASM assessment of {domain}.

Key Findings:
- Subdomains Discovered: {summary.get('total_subdomains', 0)}
- Open Ports Identified: {summary.get('total_ports', 0)}
- HTTP Assets Found: {summary.get('total_http_assets', 0)}
- Vulnerabilities Detected: {summary.get('total_vulnerabilities', 0)}
- Risk Score: {summary.get('risk_score', 0)}/100

Vulnerability Breakdown:
- Critical: {vuln_breakdown.get('critical', 0)}
- High: {vuln_breakdown.get('high', 0)}
- Medium: {vuln_breakdown.get('medium', 0)}
- Low: {vuln_breakdown.get('low', 0)}
- Info: {vuln_breakdown.get('info', 0)}
    """)

    # Subdomains
    pdf.add_page()
    pdf.chapter_title(f"Subdomains ({summary.get('total_subdomains', 0)})")

    subdomains = report_data.get("subdomains", [])
    if subdomains:
        sub_data = [[s.get("subdomain", "")] for s in subdomains[:50]]
        pdf.add_table(["Subdomain"], sub_data, [190])
        if len(subdomains) > 50:
            pdf.body_text(f"... and {len(subdomains) - 50} more")
    else:
        pdf.body_text("No subdomains discovered.")

    # Open Ports
    pdf.add_page()
    pdf.chapter_title(f"Open Ports ({summary.get('total_ports', 0)})")

    ports = report_data.get("ports", [])
    if ports:
        port_data = [
            [p.get("host", ""), str(p.get("port", "")), p.get("status", "open")]
            for p in ports[:50]
        ]
        pdf.add_table(["Host", "Port", "Status"], port_data, [100, 40, 50])
    else:
        pdf.body_text("No open ports discovered.")

    # HTTP Assets
    pdf.add_page()
    pdf.chapter_title(f"HTTP Assets ({summary.get('total_http_assets', 0)})")

    http_assets = report_data.get("http_assets", [])
    if http_assets:
        http_data = [
            [
                str(a.get("url", ""))[:40],
                str(a.get("status_code", "")),
                str(a.get("title", ""))[:30]
            ]
            for a in http_assets[:30]
        ]
        pdf.add_table(["URL", "Status", "Title"], http_data, [90, 25, 75])
    else:
        pdf.body_text("No HTTP assets discovered.")

    # Technologies
    pdf.section_title("Technologies Detected")
    technologies = report_data.get("technologies", [])
    if technologies:
        tech_text = ", ".join([f"{t[0]} ({t[1]})" for t in technologies[:15]])
        pdf.body_text(tech_text)
    else:
        pdf.body_text("No technologies detected.")

    # Vulnerabilities
    pdf.add_page()
    pdf.chapter_title(f"Vulnerabilities ({summary.get('total_vulnerabilities', 0)})")

    vulnerabilities = report_data.get("vulnerabilities", [])
    if vulnerabilities:
        vulns_by_severity = report_data.get("vulns_by_severity", {})
        for severity in ["critical", "high", "medium", "low", "info"]:
            sevs = vulns_by_severity.get(severity, [])
            if sevs:
                pdf.section_title(f"{severity.upper()} ({len(sevs)})")
                for vuln in sevs[:10]:
                    pdf.body_text(
                        f"- {vuln.get('name', 'Unknown')} - {vuln.get('severity', 'info')}")
    else:
        pdf.body_text("No vulnerabilities detected.")

    # Save PDF
    filename = f"report_{safe_domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    filepath = os.path.join("generated_reports", filename)

    pdf.output(filepath)
    print(f"[PDF] Report saved: {filepath}")

    return filepath
