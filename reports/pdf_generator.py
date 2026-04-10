"""
PDF Report Generator - Fixed Version
"""

import os
from datetime import datetime
from fpdf import FPDF


class EASMReport(FPDF):
    """Custom PDF class with consistent headers, footers, and styling."""

    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=15)

    def header(self):
        """Auto-generated header on every page."""
        self.set_font("Helvetica", "B", 12)
        self.cell(0, 10, "EASM Security Report", align="C", ln=True)
        self.ln(3)

    def footer(self):
        """Auto-generated footer with page number."""
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.cell(0, 10, f"Page {self.page_no()}", align="C")

    def chapter_title(self, title):
        """Dark banner with white text for section headers."""
        self.set_font("Helvetica", "B", 14)
        self.set_fill_color(52, 73, 94)
        self.set_text_color(255, 255, 255)
        self.cell(0, 10, title, ln=True, fill=True)
        self.set_text_color(0, 0, 0)
        self.ln(5)

    def section_title(self, title):
        """Colored subtitle without background."""
        self.ln(3)
        self.set_font("Helvetica", "B", 11)
        self.set_text_color(52, 73, 94)
        self.cell(0, 8, title, ln=True)
        self.set_text_color(0, 0, 0)
        self.ln(2)

    def body_text(self, text):
        """Multi-line body text with auto-wrapping."""
        self.set_font("Helvetica", "", 10)
        self.multi_cell(0, 6, str(text))
        self.ln(3)

    def bullet_item(self, text):
        """Single bullet item with tighter spacing."""
        self.set_font("Helvetica", "", 10)
        self.cell(8, 6, chr(149), ln=False)
        self.multi_cell(0, 6, str(text))
        self.ln(1)

    def bullet_list(self, items):
        """Render a list of bullet points with proper spacing."""
        for item in items:
            self.bullet_item(item)
        self.ln(2)

    def add_table(self, headers, data, col_widths=None):
        """
        Add a bordered table with header row.
        """
        self.ln(2)
        
        # Header row
        self.set_font("Helvetica", "B", 9)
        self.set_fill_color(240, 240, 240)

        if col_widths is None:
            col_widths = [190 // len(headers)] * len(headers)

        for i, header in enumerate(headers):
            self.cell(
                col_widths[i], 8, str(header)[:25],
                border=1, fill=True, align="L"
            )
        self.ln()

        # Data rows
        self.set_font("Helvetica", "", 8)
        for row in data[:50]:
            for i, cell in enumerate(row):
                max_chars = max(15, int(col_widths[i] / 2.2))
                text = str(cell)[:max_chars]
                self.cell(col_widths[i], 7, text, border=1, align="L")
            self.ln()
        
        self.ln(3)


def generate_pdf(report_data):
    """Generate a PDF report from structured report data."""
    
    domain = report_data.get("meta", {}).get("domain", "unknown")
    safe_domain = domain.replace(".", "_")

    os.makedirs("generated_reports", exist_ok=True)

    pdf = EASMReport()
    pdf.add_page()

    summary = report_data.get("summary", {})
    vuln_breakdown = report_data.get("vuln_breakdown", {})
    email_stats = report_data.get("email_stats", {})

    # ─── Page 1: Cover Page ──────────────────────────────
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

    risk_score = summary.get("risk_score", 0)
    pdf.ln(20)
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, f"Risk Score: {risk_score}/100", align="C", ln=True)

    # ─── Page 2: Executive Summary ───────────────────────
    pdf.add_page()
    pdf.chapter_title("Executive Summary")

    pdf.body_text(
        f"This report presents findings from an External Attack "
        f"Surface Management (EASM) assessment of {domain}."
    )

    # Key Findings
    pdf.section_title("Key Findings")
    pdf.bullet_list([
        f"Subdomains Discovered: {summary.get('total_subdomains', 0)}",
        f"Open Ports Identified: {summary.get('total_ports', 0)}",
        f"HTTP Assets Found: {summary.get('total_http_assets', 0)}",
        f"Vulnerabilities Detected: {summary.get('total_vulnerabilities', 0)}",
        f"Emails Discovered: {summary.get('total_emails', 0)}",
        f"Breached Emails: {summary.get('total_breached_emails', 0)}",
        f"Risk Score: {risk_score}/100 ({summary.get('risk_level', 'N/A')})"
    ])

    # Vulnerability Breakdown
    pdf.section_title("Vulnerability Breakdown")
    pdf.bullet_list([
        f"Critical: {vuln_breakdown.get('critical', 0)}",
        f"High: {vuln_breakdown.get('high', 0)}",
        f"Medium: {vuln_breakdown.get('medium', 0)}",
        f"Low: {vuln_breakdown.get('low', 0)}",
        f"Info: {vuln_breakdown.get('info', 0)}"
    ])

    # Email Exposure
    pdf.section_title("Email Exposure")
    pdf.bullet_list([
        f"Total Emails Found: {email_stats.get('total', 0)}",
        f"Breached: {email_stats.get('breached', 0)}",
        f"Password Leaks: {email_stats.get('password_leaks', 0)}",
        f"Breach Rate: {email_stats.get('breach_rate', 0)}%"
    ])

    # Recommendations
    recommendations = report_data.get("recommendations", [])
    if recommendations:
        pdf.section_title("Recommendations")
        for rec in recommendations:
            pdf.bullet_item(
                f"[{rec.get('priority', 'N/A')}] "
                f"{rec.get('action', '')} "
                f"(Timeframe: {rec.get('timeframe', 'N/A')})"
            )
        pdf.ln(2)

    # ─── Page 3: Subdomains ──────────────────────────────
    pdf.add_page()
    pdf.chapter_title(f"Subdomains ({summary.get('total_subdomains', 0)})")

    subdomains = report_data.get("subdomains", [])
    if subdomains:
        sub_data = [
            [
                s.get("subdomain", ""),
                ", ".join(s.get("sources", []))[:25]
            ]
            for s in subdomains[:50]
        ]
        pdf.add_table(["Subdomain", "Sources"], sub_data, [140, 50])
        if len(subdomains) > 50:
            pdf.body_text(f"... and {len(subdomains) - 50} more")
    else:
        pdf.body_text("No subdomains discovered.")

    # ─── Page 4: Open Ports ──────────────────────────────
    pdf.add_page()
    pdf.chapter_title(f"Open Ports ({summary.get('total_ports', 0)})")

    ports = report_data.get("ports", [])
    if ports:
        port_data = [
            [
                p.get("host", ""),
                str(p.get("port", "")),
                p.get("status", "open")
            ]
            for p in ports[:50]
        ]
        pdf.add_table(["Host", "Port", "Status"], port_data, [100, 40, 50])
        if len(ports) > 50:
            pdf.body_text(f"... and {len(ports) - 50} more")
    else:
        pdf.body_text("No open ports discovered.")

    # ─── Page 5: HTTP Assets ─────────────────────────────
    pdf.add_page()
    pdf.chapter_title(f"HTTP Assets ({summary.get('total_http_assets', 0)})")

    http_assets = report_data.get("http_assets", [])
    if http_assets:
        http_data = [
            [
                str(a.get("url", ""))[:70],
                str(a.get("status_code", "")),
                str(a.get("title", ""))[:25]
            ]
            for a in http_assets[:30]
        ]
        pdf.add_table(["URL", "Status", "Title"], http_data, [115, 20, 55])
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

    # ─── Page 6: Vulnerabilities ─────────────────────────
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
                    name = vuln.get("name", "Unknown")
                    host = vuln.get("host", "")
                    cve = vuln.get("cve_id", "")
                    line = f"{name}"
                    if cve:
                        line += f" ({cve})"
                    if host:
                        line += f" @ {host}"
                    pdf.bullet_item(line)
                if len(sevs) > 10:
                    pdf.body_text(f"... and {len(sevs) - 10} more {severity} findings")
    else:
        pdf.body_text("No vulnerabilities detected.")

    # ─── Page 7: Email Exposure ──────────────────────────
    pdf.add_page()
    pdf.chapter_title(f"Email Exposure ({email_stats.get('total', 0)})")

    emails = report_data.get("emails", [])

    if email_stats.get("total", 0) > 0:
        pdf.section_title("Email Exposure Summary")
        pdf.bullet_list([
            f"Total Emails Discovered: {email_stats.get('total', 0)}",
            f"Breached Emails: {email_stats.get('breached', 0)}",
            f"Clean Emails: {email_stats.get('clean', 0)}",
            f"Unchecked Emails: {email_stats.get('unchecked', 0)}",
            f"Password Leaks: {email_stats.get('password_leaks', 0)}",
            f"Breach Rate: {email_stats.get('breach_rate', 0)}%"
        ])

        # Breached emails table
        breached_emails = [
            e for e in emails
            if e.get("breach_status") == "breached"
        ]
        if breached_emails:
            pdf.section_title(f"Breached Emails ({len(breached_emails)})")

            breach_data = []
            for e in breached_emails[:30]:
                breach_names = ", ".join(
                    b.get("name", "") for b in e.get("breaches", [])[:3]
                )[:40]
                breach_data.append([
                    str(e.get("email", ""))[:35],
                    str(e.get("breach_count", 0)),
                    "Yes" if e.get("password_leaked") else "No",
                    breach_names
                ])

            pdf.add_table(
                ["Email", "Breaches", "Pwd Leaked", "Breach Names"],
                breach_data,
                [70, 25, 30, 65]
            )

            if len(breached_emails) > 30:
                pdf.body_text(f"... and {len(breached_emails) - 30} more breached emails")

        # Clean emails table
        clean_emails = [
            e for e in emails
            if e.get("breach_status") != "breached"
        ]
        if clean_emails:
            pdf.section_title(f"Other Discovered Emails ({len(clean_emails)})")
            all_email_data = [
                [
                    str(e.get("email", ""))[:40],
                    str(e.get("breach_status", "unknown")),
                    ", ".join(e.get("sources", []))[:30]
                ]
                for e in clean_emails[:50]
            ]
            pdf.add_table(
                ["Email", "Status", "Sources"],
                all_email_data,
                [80, 40, 70]
            )
            if len(clean_emails) > 50:
                pdf.body_text(f"... and {len(clean_emails) - 50} more")
    else:
        pdf.body_text("No email exposures discovered.")

    # ─── Save PDF ────────────────────────────────────────
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"report_{safe_domain}_{timestamp}.pdf"
    filepath = os.path.join("generated_reports", filename)

    pdf.output(filepath)
    print(f"[PDF] Report saved: {filepath}")

    return filepath