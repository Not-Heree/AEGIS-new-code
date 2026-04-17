"""
PDF Report Generator - Compliance-Ready Report
===============================================
Uses fpdf2 with start_section/insert_toc_placeholder for
auto-generated Table of Contents with correct page numbers.

All text uses latin-1 safe characters only (no unicode dashes/bullets).
Tables use multi_cell for wrapping instead of clipping.
"""

import os
import hashlib
import re
from datetime import datetime
from fpdf import FPDF


# ═══════════════════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def _safe(text):
    """Encode to latin-1 safe characters for fpdf core fonts."""
    if text is None:
        return ""
    return str(text).encode("latin-1", "replace").decode("latin-1")


def _risk_color(score):
    if score >= 76:
        return (192, 57, 43)
    elif score >= 56:
        return (211, 84, 0)
    elif score >= 31:
        return (243, 156, 18)
    else:
        return (46, 204, 113)


def _risk_label(score):
    if score >= 76:
        return "CRITICAL"
    elif score >= 56:
        return "HIGH"
    elif score >= 31:
        return "MODERATE"
    else:
        return "LOW"


def _flatten_details(details):
    """Convert a change details field to readable string.
    Handles both string and dict formats."""
    if isinstance(details, str):
        return details
    if isinstance(details, dict):
        parts = []
        for k, v in details.items():
            if v and str(v).strip():
                parts.append(f"{k}: {v}")
        return " | ".join(parts) if parts else "N/A"
    return str(details)


def _get_subdomain_ip(sub):
    """Extract the best IP string from a subdomain document."""
    ips = sub.get("ip_addresses", [])
    if ips and isinstance(ips, list):
        return str(ips[0]) if ips[0] else "-"
    ip = sub.get("ip", "")
    return str(ip) if ip else "-"


def _clean_breach_name(breach):
    """
    Extract human-readable breach name.
    Filters out stealer logs, raw file paths, and garbage strings.
    """
    if isinstance(breach, dict):
        name = breach.get("name", "") or breach.get("title", "")
    else:
        name = str(breach)

    # Strip file paths
    if "/" in name:
        name = name.split("/")[0]
    if "\\" in name:
        name = name.split("\\")[0]

    # Strip file extensions
    for ext in [".txt", ".csv", ".sql", ".json", ".rar", ".zip", ".gz", ".7z"]:
        name = name.replace(ext, "")

    # Detect obvious stealer log / garbage indicators
    garbage_indicators = [
        "[DISABLED]", "[bm ", "[INR]", "[limit", "[balance",
        "[billing", "[pages", "[cards", "GMGEVR", "_y1Ly",
    ]
    if any(g in name for g in garbage_indicators):
        return "Underground data collection"

    # Detect hash-like strings (long hex in brackets)
    if re.search(r'\[([A-Fa-f0-9]{16,})\]', name):
        return "Underground data collection"

    # Detect timestamp patterns from stealer logs
    if re.search(r'\d{4}-\d{2}-\d{2}T\d{2}', name):
        return "Underground data collection"

    # Detect IP-based filenames
    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', name):
        return "Underground data collection"

    # Detect compilation/aggregate breach dumps
    compilation_indicators = [
        "PART IV", "PART I", "PART II", "PART III",
        "CORP APB", "000 000", "CompilationOfMany",
        "Collection #", "DATA_PERSON", "SSN LEAKED",
    ]
    if any(c in name for c in compilation_indicators):
        return "Compilation breach dataset"

    # Detect truncated URLs
    if name.strip() in ["https:", "http:", "ftp:", ""]:
        return "Unknown breach source"

    name = name.strip()
    return name if name and len(name) > 2 else "Unknown breach"


DANGEROUS_PORTS = {
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP Relay",
    110:   "POP3",
    143:   "IMAP",
    445:   "SMB",
    3389:  "RDP",
    5900:  "VNC",
    1433:  "MSSQL",
    3306:  "MySQL",
    5432:  "PostgreSQL",
    6379:  "Redis",
    27017: "MongoDB",
    11211: "Memcached",
    9200:  "Elasticsearch",
    8080:  "HTTP-Alt",
    8443:  "HTTPS-Alt",
}

# Ports that are truly high risk (not just elevated)
HIGH_RISK_PORTS = {21, 23, 445, 3389, 5900, 6379, 27017, 11211, 9200}

SECURITY_HEADERS_LIST = [
    ("strict-transport-security",   "HSTS",                "Medium", "Prevents SSL stripping attacks"),
    ("content-security-policy",     "CSP",                 "High",   "Prevents cross-site scripting (XSS)"),
    ("x-frame-options",             "X-Frame-Options",     "Medium", "Prevents clickjacking attacks"),
    ("x-content-type-options",      "X-Content-Type",      "Low",    "Prevents MIME sniffing"),
    ("referrer-policy",             "Referrer-Policy",     "Low",    "Prevents information leakage"),
    ("permissions-policy",          "Permissions-Policy",  "Low",    "Controls browser feature access"),
]

OUTDATED_TECH_FLAGS = {
    "jquery":    "Verify version - older versions have known XSS CVEs",
    "wordpress": "Verify version and plugins - frequent CVE target",
    "drupal":    "Verify version - Drupalgeddon vulnerability history",
    "php":       "Verify not EOL - PHP 7.x is end-of-life, no patches",
    "java":      "Verify version - check for Log4Shell (CVE-2021-44228)",
    "nginx":     "Verify version against NVD for known CVEs",
    "apache":    "Verify version - check for CVE-2021-41773 and others",
    "tomcat":    "Verify version against known Apache Tomcat CVEs",
    "iis":       "Verify version and patch level",
    "openssl":   "Verify version - check for Heartbleed and newer CVEs",
    "bootstrap": "Verify version - older versions have XSS vulnerabilities",
    "angular":   "Verify version against known Angular CVEs",
}


# ═══════════════════════════════════════════════════════════════════════════
#  PDF CLASS
# ═══════════════════════════════════════════════════════════════════════════

class EASMReport(FPDF):

    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=15)

    def header(self):
        self.set_font("Helvetica", "B", 7)
        self.set_text_color(180, 40, 40)
        self.cell(0, 4, "CONFIDENTIAL - FOR AUTHORIZED RECIPIENTS ONLY",
                  align="C", new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(200, 200, 200)
        self.line(10, self.get_y(), 200, self.get_y())
        self.set_text_color(0, 0, 0)
        self.ln(2)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 7)
        self.set_text_color(150, 150, 150)
        self.cell(95, 10, "EASM AEGIS Platform", align="L")
        self.cell(95, 10, f"Page {self.page_no()}/{{nb}}", align="R")
        self.set_text_color(0, 0, 0)

    # ── Formatting helpers ───────────────────────────────────────────

    def chapter_title(self, title):
        self.start_section(title)
        self.set_font("Helvetica", "B", 13)
        self.set_fill_color(44, 62, 80)
        self.set_text_color(255, 255, 255)
        self.cell(0, 9, _safe(f"  {title}"), new_x="LMARGIN", new_y="NEXT", fill=True)
        self.set_text_color(0, 0, 0)
        self.ln(4)

    def sub_title(self, title):
        self.ln(2)
        self.set_font("Helvetica", "B", 11)
        self.set_text_color(44, 62, 80)
        self.cell(0, 7, _safe(title), new_x="LMARGIN", new_y="NEXT")
        self.set_text_color(0, 0, 0)
        self.ln(2)

    def body(self, text):
        self.set_font("Helvetica", "", 9)
        self.multi_cell(0, 5, _safe(text))
        self.ln(2)

    def bold_body(self, text):
        self.set_font("Helvetica", "B", 9)
        self.multi_cell(0, 5, _safe(text))
        self.ln(2)

    def bullet(self, text):
        self.set_font("Helvetica", "", 9)
        self.cell(6, 5, "-")
        self.multi_cell(0, 5, _safe(text))
        self.ln(1)

    def bullets(self, items):
        for item in items:
            self.bullet(item)
        self.ln(2)

    def kv_line(self, key, value):
        self.set_font("Helvetica", "B", 9)
        self.cell(55, 5, _safe(key))
        self.set_font("Helvetica", "", 9)
        self.cell(0, 5, _safe(str(value)), new_x="LMARGIN", new_y="NEXT")

    def stat_row(self, label, value, warn=False):
        self.set_font("Courier", "", 9)
        flag = "  (!)" if warn else ""
        self.cell(0, 5, _safe(f"  {label:<42} {str(value):>8}{flag}"),
                  new_x="LMARGIN", new_y="NEXT")

    def table(self, headers, rows, widths=None):
        """Table with proper text wrapping — no clipping."""
        if not widths:
            widths = [190 // len(headers)] * len(headers)
        self.ln(1)

        # Header row
        self.set_font("Helvetica", "B", 8)
        self.set_fill_color(44, 62, 80)
        self.set_text_color(255, 255, 255)
        for i, h in enumerate(headers):
            self.cell(widths[i], 7, _safe(str(h)), border=1, fill=True)
        self.ln()
        self.set_text_color(0, 0, 0)

        # Data rows
        self.set_font("Helvetica", "", 7.5)
        for ri, row in enumerate(rows):
            fill_color = (248, 249, 250) if ri % 2 == 0 else (255, 255, 255)
            self.set_fill_color(*fill_color)

            # Calculate row height from longest cell
            max_lines = 1
            for i, cell_val in enumerate(row):
                text = _safe(str(cell_val))
                char_per_line = max(1, int(widths[i] / 1.85))
                lines = max(1, (len(text) + char_per_line - 1) // char_per_line)
                max_lines = max(max_lines, lines)
            row_h = max(6, min(max_lines * 4.5, 24))

            # Draw cells
            for i, cell_val in enumerate(row):
                text = _safe(str(cell_val))
                x = self.get_x()
                y = self.get_y()
                # Background
                self.set_fill_color(*fill_color)
                self.rect(x, y, widths[i], row_h, style="F")
                # Border
                self.rect(x, y, widths[i], row_h, style="")
                # Text
                self.set_xy(x + 1, y + 1)
                self.multi_cell(widths[i] - 2, 4.5, text, border=0)
                self.set_xy(x + widths[i], y)
            self.ln(row_h)

            # Manual page break if needed
            if self.get_y() > 272:
                self.add_page()
                self.set_font("Helvetica", "", 7.5)
        self.ln(2)

    def alert_box(self, title, text, color=(211, 84, 0)):
        r, g, b = color
        if self.get_y() > 248:
            self.add_page()
        self.set_fill_color(r, g, b)
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 9)
        self.cell(0, 7, _safe(f"  {title}"), new_x="LMARGIN", new_y="NEXT", fill=True)
        self.set_text_color(0, 0, 0)
        self.set_fill_color(252, 252, 252)
        self.set_font("Courier", "", 8)
        self.multi_cell(0, 4.5, _safe(text), border="LRB", fill=True)
        self.ln(4)

    def finding_sheet(self, vuln, num, severity):
        if self.get_y() > 190:
            self.add_page()

        cve        = vuln.get("cve_id", "No CVE")
        name       = vuln.get("name", vuln.get("template_id", "Unknown"))
        host       = vuln.get("host", "N/A")
        cvss       = vuln.get("cvss_score", vuln.get("severity_score", "N/A"))
        rem        = vuln.get("remediation", {}) or {}
        epss       = vuln.get("epss", {}) or {}
        desc       = vuln.get("description", "")
        kev        = vuln.get("kev_data") or vuln.get("is_kev")
        comp       = rem.get("compliance", "")

        sev_colors = {"CRITICAL": (192, 57, 43), "HIGH": (211, 84, 0)}
        r, g, b = sev_colors.get(severity, (44, 62, 80))

        self.set_fill_color(r, g, b)
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 9)
        self.cell(0, 7, _safe(f"  FINDING #{num}  |  {severity}  |  {cve}"),
                  new_x="LMARGIN", new_y="NEXT", fill=True)
        self.set_text_color(0, 0, 0)

        lines = [
            f"Name:        {name}",
            f"Host:        {host}",
            f"CVSS Score:  {cvss}",
        ]
        if epss.get("score"):
            lines.append(f"EPSS Score:  {epss.get('score')} "
                         f"(top {epss.get('percentage', 'N/A')}% exploitation probability)")
        if kev:
            lines.append("KEV Status:  *** IN CISA KNOWN EXPLOITED LIST ***")
        if comp:
            lines.append(f"Controls:    {comp}")
        if desc:
            lines.append("")
            lines.append(f"Description: {str(desc)[:300]}")
        lines.append("")
        lines.append(f"Remediation: {rem.get('summary', 'Refer to vendor advisory.')}")

        self.set_fill_color(252, 252, 252)
        self.set_font("Courier", "", 8)
        self.multi_cell(0, 4.5, _safe("\n".join(lines)), border="LRB", fill=True)
        self.ln(5)


# ═══════════════════════════════════════════════════════════════════════════
#  TOC RENDERER  (module-level — not a method)
# ═══════════════════════════════════════════════════════════════════════════

def render_toc(pdf, outline):
    """Callback for fpdf2 insert_toc_placeholder."""
    pdf.ln(5)
    pdf.set_font("Helvetica", "B", 18)
    pdf.set_text_color(44, 62, 80)
    pdf.multi_cell(190, 14, "Table of Contents", align="C")
    pdf.set_text_color(0, 0, 0)
    pdf.ln(6)
    pdf.set_draw_color(200, 200, 200)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(4)
    pdf.set_font("Helvetica", "", 10)
    for s in outline:
        indent = "   " * s.level
        label  = _safe(f"{indent}{s.name}")
        dots   = "." * max(1, 68 - len(label))
        pdf.cell(155, 7, _safe(f"{label} {dots}"), border=0)
        pdf.cell(35,  7, str(s.page_number), border=0,
                 align="R", new_x="LMARGIN", new_y="NEXT")


# ═══════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════

def generate_pdf(report_data, report_type="domain"):
    if report_type == "overall":
        return _generate_overall_pdf(report_data)
    return _generate_domain_pdf(report_data)


# ═══════════════════════════════════════════════════════════════════════════
#  DOMAIN REPORT
# ═══════════════════════════════════════════════════════════════════════════

def _generate_domain_pdf(report_data):
    domain      = report_data.get("meta", {}).get("domain", "unknown")
    safe_domain = domain.replace(".", "_")
    os.makedirs("generated_reports", exist_ok=True)

    pdf = EASMReport()
    pdf.alias_nb_pages()

    # ── Extract all data ─────────────────────────────────────────────
    summary        = report_data.get("summary", {})
    vuln_breakdown = report_data.get("vuln_breakdown", {})
    email_stats    = report_data.get("email_stats", {})
    risk_score     = summary.get("risk_score", 0)
    risk_level     = _risk_label(risk_score)
    target         = report_data.get("target", {})

    generated_at = report_data.get("meta", {}).get("generated_at", "")[:19]
    scan_info    = report_data.get("latest_scan") or {}
    report_id    = hashlib.md5(f"{domain}{generated_at}".encode()).hexdigest()[:12].upper()

    subdomains       = report_data.get("subdomains", [])
    ports            = report_data.get("ports", [])
    http_assets      = report_data.get("http_assets", [])
    vulns_list       = report_data.get("vulnerabilities", [])
    vulns_by_sev     = report_data.get("vulns_by_severity", {})
    emails           = report_data.get("emails", [])
    changes          = report_data.get("changes", [])
    technologies     = report_data.get("technologies", [])
    whois_data       = report_data.get("whois") or {}
    shodan_data      = report_data.get("shodan") or {}
    censys_data      = report_data.get("censys") or {}
    recommendations  = report_data.get("recommendations", [])

    total_vulns  = summary.get("total_vulnerabilities", 0)
    crit         = vuln_breakdown.get("critical", 0)
    high         = vuln_breakdown.get("high", 0)
    med          = vuln_breakdown.get("medium", 0)
    low          = vuln_breakdown.get("low", 0)
    info_count   = vuln_breakdown.get("info", 0)
    subs_count   = summary.get("total_subdomains", 0)
    assets_count = summary.get("total_http_assets", 0)
    breached     = email_stats.get("breached", 0)
    total_emails = email_stats.get("total", 0)
    breach_rate  = email_stats.get("breach_rate", 0)
    pwd_leaks    = email_stats.get("password_leaks", 0)

    kev_count   = sum(1 for v in vulns_list if v.get("kev_data") or v.get("is_kev"))
    epss_scores = [float(v["epss"]["score"]) for v in vulns_list
                   if v.get("epss") and v["epss"].get("score")]
    avg_epss    = round(sum(epss_scores) / len(epss_scores), 3) if epss_scores else None

    # Unique services
    unique_services = set()
    port_map = {443: "https", 80: "http", 53: "dns", 22: "ssh",
                21: "ftp", 25: "smtp", 3306: "mysql", 5432: "postgres"}
    for p in ports:
        svc = p.get("service", "")
        if svc:
            unique_services.add(svc.lower())
        else:
            pn = p.get("port", 0)
            if pn in port_map:
                unique_services.add(port_map[pn])

    count_429  = sum(1 for a in http_assets if a.get("status_code") == 429)
    https_count = sum(1 for a in http_assets if str(a.get("url", "")).startswith("https"))
    http_only   = len(http_assets) - https_count
    dangerous   = sum(1 for p in ports if p.get("port") in DANGEROUS_PORTS)

    # Security headers — built from http_assets if headers available,
    # or from dedicated security_headers field in report_data
    raw_sec_headers = report_data.get("security_headers", [])
    if not raw_sec_headers and http_assets:
        # Try to derive from assets that have response headers stored
        for asset in http_assets:
            hdrs = asset.get("headers", asset.get("response_headers", {})) or {}
            if not hdrs:
                continue
            hdrs_lower = {k.lower(): v for k, v in hdrs.items()}
            missing = [label for hdr, label, _, _ in SECURITY_HEADERS_LIST
                       if hdr not in hdrs_lower]
            if missing:
                raw_sec_headers.append({
                    "host":    asset.get("url", asset.get("host", "")),
                    "missing": ", ".join(missing),
                })

    org_display = target.get("org_name", "") or domain

    # ══════════════════════════════════════════════════════════════════
    # COVER PAGE
    # ══════════════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.ln(15)

    pdf.set_font("Helvetica", "B", 28)
    pdf.set_text_color(44, 62, 80)
    pdf.cell(0, 14, "EASM AEGIS", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 13)
    pdf.cell(0, 8, "External Attack Surface Assessment Report",
             align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)
    pdf.ln(10)

    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(41, 128, 185)
    pdf.cell(0, 12, _safe(domain), align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)
    pdf.ln(10)

    r, g, b = _risk_color(risk_score)
    pdf.set_fill_color(r, g, b)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 30)
    x_center = (210 - 60) / 2
    pdf.set_xy(x_center, pdf.get_y())
    pdf.cell(60, 18, f"{risk_score}/100", align="C", fill=True,
             new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(r, g, b)
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 8, f"Risk Level: {risk_level}", align="C",
             new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)
    pdf.ln(10)

    pdf.set_font("Helvetica", "", 10)
    for line in [
        f"Report ID:       RPT-{report_id}",
        f"Target:          {domain}",
        f"Organization:    {org_display}",
        f"Scan Date:       {str(scan_info.get('started_at', generated_at))[:19]}",
        f"Generated:       {generated_at}",
        f"Prepared By:     EASM AEGIS Security Platform",
        f"Classification:  CONFIDENTIAL",
    ]:
        pdf.cell(0, 6, _safe(line), align="C", new_x="LMARGIN", new_y="NEXT")

    pdf.ln(8)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(130, 130, 130)
    pdf.cell(0, 5, "This document contains sensitive security findings.",
             align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 5, "Unauthorized distribution is prohibited.",
             align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)

    pdf.insert_toc_placeholder(render_toc, pages=2)

    # ══════════════════════════════════════════════════════════════════
    # 1. EXECUTIVE SUMMARY
    # ══════════════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.chapter_title("1. Executive Summary")

    exec_parts = [
        f"The assessment of {domain} identified {total_vulns} vulnerabilities across "
        f"{assets_count} live hosts, including {crit} critical and {high} high-severity issues."
    ]
    if kev_count > 0:
        exec_parts.append(
            f"{kev_count} of these are listed in CISA's Known Exploited Vulnerabilities "
            f"catalog and require immediate attention."
        )
    if breached > 0 and total_emails > 0:
        exec_parts.append(
            f"{breached} out of {total_emails} employee emails ({breach_rate}%) were "
            f"found in known data breaches."
        )
    exec_parts.append(f"The overall risk score is {risk_score}/100 ({risk_level}).")
    pdf.body(" ".join(exec_parts))

    pdf.sub_title("Key Metrics")
    epss_display = str(avg_epss) if avg_epss is not None else "N/A (no CVEs with EPSS data)"
    pdf.table(
        ["Metric", "Value"],
        [
            ["Subdomains Discovered",  str(subs_count)],
            ["Live HTTP Assets",       str(assets_count)],
            ["Open Ports",             str(summary.get("total_ports", len(ports)))],
            ["Unique Services",        str(len(unique_services)) if unique_services else "N/A"],
            ["Total Vulnerabilities",  str(total_vulns)],
            ["Critical / High",        f"{crit} / {high}"],
            ["CISA KEV Matches",       str(kev_count) if kev_count else "None"],
            ["Avg EPSS Score",         epss_display],
            ["Emails Discovered",      str(total_emails)],
            ["Breached Emails",        f"{breached} ({breach_rate}%)"],
            ["Password Leaks",         str(pwd_leaks)],
            ["Risk Score",             f"{risk_score}/100 [{risk_level}]"],
        ],
        [110, 80]
    )

    if count_429 > 0:
        pdf.alert_box(
            f"SCANNER NOTICE: {count_429} hosts returned HTTP 429 (Rate Limited)",
            f"{count_429} out of {assets_count} HTTP assets returned 429 Too Many Requests.\n"
            f"Results for these hosts may be incomplete. A slower rescan is recommended.",
            color=(243, 156, 18)
        )

    pdf.sub_title("Risk Gauge")
    pdf.set_font("Courier", "B", 9)
    gauge_pos = int(risk_score / 100 * 40)
    bar = "[" + "#" * gauge_pos + "-" * (40 - gauge_pos) + "]"
    pdf.cell(0, 5, _safe(f"  LOW {bar} CRITICAL"), new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 5, _safe(f"       {' ' * gauge_pos}^ {risk_score}/100"),
             new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    pdf.sub_title("Business Impact")
    impact_parts = []
    if breach_rate and float(str(breach_rate).replace("%", "")) >= 50 and breached > 5:
        impact_parts.append(
            f"The most significant finding is that {breached} of {total_emails} employee "
            f"emails ({breach_rate}%) appear in known data breaches"
            f"{f', with {pwd_leaks} having leaked passwords' if pwd_leaks else ''}. "
            f"This creates direct account takeover risk for VPN, email, and internal systems."
        )
    if crit > 0:
        impact_parts.append(
            f"{crit} critical vulnerabilities pose an immediate risk of unauthorized "
            f"access, data exfiltration, or full system compromise."
        )
    if kev_count > 0:
        impact_parts.append(
            f"{kev_count} vulnerabilities are confirmed actively exploited in the wild, "
            f"increasing the probability of a targeted attack."
        )
    if not impact_parts:
        if risk_score >= 56:
            impact_parts.append(
                "The security posture has notable gaps that increase the probability of "
                "compromise. Remediation should be prioritized within the current cycle."
            )
        elif risk_score >= 31:
            impact_parts.append(
                "The attack surface has moderate exposure. No immediately critical threats "
                "were identified, but several findings should be addressed in the next "
                "maintenance window."
            )
        else:
            impact_parts.append(
                "The organization maintains a strong external security posture. "
                "Continue regular monitoring and periodic reassessment."
            )
    pdf.body(" ".join(impact_parts))

    # ══════════════════════════════════════════════════════════════════
    # 2. ATTACK SURFACE OVERVIEW
    # ══════════════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.chapter_title("2. Attack Surface Overview")

    live_subs = sum(1 for s in subdomains if s.get("is_alive", True))
    dead_subs = len(subdomains) - live_subs

    pdf.sub_title("Discovery")
    pdf.stat_row("Total Subdomains Found",    subs_count)
    pdf.stat_row("Live / Resolving Hosts",    live_subs)
    pdf.stat_row("Dead / Unresolved",         dead_subs, warn=dead_subs > 0)
    pdf.ln(3)

    pdf.sub_title("Network Exposure")
    pdf.stat_row("Total Open Ports",          len(ports))
    pdf.stat_row("Unique Services Running",   len(unique_services) if unique_services else "N/A")
    pdf.stat_row("Dangerous Ports Exposed",   dangerous, warn=dangerous > 0)
    pdf.ln(3)

    pdf.sub_title("Web Presence")
    pdf.stat_row("HTTP Assets Discovered",    assets_count)
    pdf.stat_row("HTTPS Assets",              https_count)
    pdf.stat_row("HTTP Only (No Encryption)", http_only, warn=http_only > 0)
    if count_429 > 0:
        pdf.stat_row("Rate Limited (HTTP 429)",  count_429, warn=True)
    pdf.ln(3)

    pdf.sub_title("Vulnerabilities")
    pdf.stat_row("Total CVEs Found",          total_vulns)
    pdf.stat_row("Critical",                  crit,      warn=crit > 0)
    pdf.stat_row("High",                      high,      warn=high > 0)
    pdf.stat_row("Medium",                    med)
    pdf.stat_row("Low",                       low)
    pdf.stat_row("CISA KEV Matches",          kev_count if kev_count else "None",
                 warn=kev_count > 0)
    pdf.stat_row("Avg EPSS Score",            avg_epss if avg_epss is not None else "N/A")
    pdf.ln(3)

    pdf.sub_title("Intelligence")
    pdf.stat_row("Emails Discovered",         total_emails)
    pdf.stat_row("Emails in Breaches",        f"{breached} ({breach_rate}%)",
                 warn=breached > 0)
    pdf.stat_row("Password Leaks",            pwd_leaks, warn=pwd_leaks > 0)
    shodan_host_count = len(shodan_data.get("hosts", []))
    if shodan_host_count:
        pdf.stat_row("Shodan Exposed Services", shodan_host_count)
    pdf.ln(3)

    pdf.set_font("Courier", "B", 10)
    pdf.set_text_color(*_risk_color(risk_score))
    pdf.cell(0, 6, _safe(f"  OVERALL RISK SCORE:  {risk_score}/100  [{risk_level}]"),
             new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)

    # ══════════════════════════════════════════════════════════════════
    # 3. METHODOLOGY & SCOPE
    # ══════════════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.chapter_title("3. Methodology & Scope")

    pdf.sub_title("3.1 Assessment Approach")
    pdf.body(
        "This assessment combines Passive Reconnaissance (Shodan, Censys, WHOIS, cert.sh, "
        "theHarvester - zero direct contact with the target) with Active Scanning (Naabu "
        "port scanning, HTTPX probing, Nuclei vulnerability detection). Passive recon "
        "carries zero legal risk to the target. Active scanning was performed against "
        "authorized targets only."
    )

    pdf.sub_title("3.2 Tools Used")
    pdf.table(
        ["Tool", "Type", "Purpose"],
        [
            ["Subfinder",     "Passive",    "Subdomain enumeration from 40+ sources"],
            ["Amass",         "Passive",    "DNS enumeration and OSINT"],
            ["Shodan API",    "Passive",    "Internet-wide service and banner data"],
            ["Censys API",    "Passive",    "Certificate transparency and TLS analysis"],
            ["WHOIS",         "Passive",    "Domain registration and ownership data"],
            ["cert.sh",       "Passive",    "Certificate transparency log analysis"],
            ["theHarvester",  "Passive",    "Email and people intelligence"],
            ["Hunter.io API", "Passive",    "Email discovery and verification"],
            ["LeakCheck API", "Passive",    "Breach database correlation"],
            ["IntelX API",    "Passive",    "OSINT aggregation"],
            ["Naabu",         "Active",     "TCP port discovery and scanning"],
            ["HTTPX",         "Active",     "HTTP probing and tech fingerprinting"],
            ["Nuclei",        "Active",     "Template-based vulnerability detection"],
            ["NVD / NIST",    "Enrichment", "CVE details and CVSS scoring"],
            ["FIRST EPSS",    "Enrichment", "Exploitation probability scoring"],
            ["CISA KEV",      "Enrichment", "Known exploited vulnerabilities list"],
        ],
        [42, 28, 120]
    )

    pdf.sub_title("3.3 Compliance Framework Alignment")
    pdf.table(
        ["Framework", "Controls", "Scope"],
        [
            ["SOC 2 Type II",  "CC6.1, CC6.6, CC6.7, CC7.1",  "Access Controls & Security Events"],
            ["ISO 27001:2022", "A.8.8, A.8.9, A.12.6, A.14.2","Technical Vulnerability Mgmt"],
            ["PCI-DSS v4.0",  "Req 6.2, 6.3, 11.3",           "Vuln Scanning & Secure Development"],
            ["OWASP Top 10",  "A01-A10:2021",                  "Web Application Risk Categories"],
        ],
        [42, 65, 83]
    )

    pdf.sub_title("3.4 Scope Definition")
    pdf.kv_line("In-Scope:",     f"{domain} and all discovered subdomains")
    pdf.kv_line("Out-of-Scope:", "Third-party CDN infrastructure, WAF-protected endpoints")
    pdf.kv_line("Scan Start:",   str(scan_info.get("started_at", "N/A"))[:19])
    pdf.kv_line("Scan End:",     str(scan_info.get("completed_at", "N/A"))[:19])

    if count_429 > 0:
        pdf.ln(3)
        pdf.alert_box(
            "SCAN LIMITATION: Rate Limiting Detected",
            f"{count_429} hosts returned HTTP 429. Findings for these may be incomplete.\n"
            f"A slower-rate rescan is recommended for full coverage.",
            color=(243, 156, 18)
        )

    # ══════════════════════════════════════════════════════════════════
    # 4. RECONNAISSANCE RESULTS
    # ══════════════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.chapter_title("4. Reconnaissance Results")

    # 4.1 WHOIS
    pdf.sub_title("4.1 WHOIS & Domain Intelligence")
    if whois_data and whois_data.get("registrar"):
        pdf.kv_line("Registrar:",    whois_data.get("registrar", "N/A"))
        pdf.kv_line("Created:",      str(whois_data.get("creation_date", "N/A"))[:10])
        pdf.kv_line("Expires:",      str(whois_data.get("expiration_date", "N/A"))[:10])
        pdf.kv_line("Name Servers:", ", ".join(whois_data.get("nameservers", [])[:3]) or "N/A")
        pdf.kv_line("DNSSEC:",       "Enabled" if whois_data.get("dnssec")
                                     else "Not configured (!)")
        pdf.kv_line("Privacy:",      "Protected" if whois_data.get("privacy_enabled")
                                     else "Exposed (!)")

        days = whois_data.get("days_until_expiry")
        if days is not None:
            try:
                d = int(float(str(days)))
                if d < 60:
                    pdf.ln(2)
                    pdf.alert_box(
                        "WARNING: DOMAIN EXPIRING SOON",
                        f"Domain expires in {d} days. An expired domain can be hijacked "
                        f"by an attacker who re-registers it and intercepts your email/traffic.",
                        color=(192, 57, 43) if d < 30 else (211, 84, 0)
                    )
            except (ValueError, TypeError):
                pass

        risk_flags = whois_data.get("risk_flags", [])
        if risk_flags:
            pdf.sub_title("WHOIS Risk Flags")
            flag_strs = []
            for f in risk_flags:
                if isinstance(f, dict):
                    flag_strs.append(f.get("detail", str(f)))
                else:
                    flag_strs.append(str(f))
            pdf.bullets(flag_strs)
    else:
        pdf.body("No WHOIS data collected for this scan.")

    # 4.2 Shodan
    pdf.sub_title("4.2 Shodan Intelligence")
    shodan_services = shodan_data.get("services", [])
    if shodan_data.get("hosts") or shodan_services:
        pdf.body(
            f"Shodan identified {len(shodan_data.get('hosts', []))} hosts and "
            f"{len(shodan_services)} services. This data represents what any attacker "
            f"on the internet can passively observe."
        )
        if shodan_services:
            svc_rows = []
            for s in shodan_services[:25]:
                ip = s.get("ip", s.get("ip_str", s.get("hostname", "-")))
                svc_rows.append([
                    str(ip)[:22],
                    str(s.get("port", "")),
                    str(s.get("product", s.get("service", "")))[:25],
                    str(s.get("version", ""))[:15],
                ])
            pdf.table(["IP / Host", "Port", "Product", "Version"],
                      svc_rows, [60, 20, 60, 50])
    else:
        pdf.body("No Shodan data available. Configure SHODAN_API_KEY to enable.")

    # 4.3 Censys (only if data exists)
    if censys_data and (censys_data.get("hosts") or censys_data.get("services")):
        pdf.sub_title("4.3 Censys Intelligence")
        pdf.body(
            f"Censys identified {len(censys_data.get('hosts', []))} hosts and "
            f"{len(censys_data.get('services', []))} services with TLS/certificate data."
        )

    # ══════════════════════════════════════════════════════════════════
    # 5. ASSET DISCOVERY
    # ══════════════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.chapter_title("5. Asset Discovery - Subdomains")

    pdf.body(
        f"{len(subdomains)} subdomains were discovered for {domain}. "
        f"Every subdomain represents a potential entry point for attackers."
    )

    # Source breakdown
    source_counts = {}
    for s in subdomains:
        for src in s.get("sources", []):
            source_counts[src] = source_counts.get(src, 0) + 1
    if source_counts:
        src_rows = [[src, str(cnt)] for src, cnt in
                    sorted(source_counts.items(), key=lambda x: x[1], reverse=True)]
        pdf.table(["Discovery Source", "Subdomains Found"], src_rows, [100, 90])

    # Full inventory
    if subdomains:
        pdf.sub_title("Subdomain Inventory")
        sub_rows = []
        for s in subdomains:
            ip     = _get_subdomain_ip(s)
            status = "Live" if s.get("is_alive", True) else "Dead"
            sub_rows.append([
                str(s.get("subdomain", ""))[:48],
                ip[:16],
                status,
                ", ".join(s.get("sources", []))[:20],
            ])
        pdf.table(["Subdomain", "IP", "Status", "Sources"],
                  sub_rows, [82, 32, 18, 58])

    # ══════════════════════════════════════════════════════════════════
    # 6. SUBDOMAIN TAKEOVER RISK
    # ══════════════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.chapter_title("6. Subdomain Takeover Risk Assessment")

    pdf.body(
        "Subdomain takeover occurs when a subdomain's DNS record points to a third-party "
        "service (AWS S3, GitHub Pages, Heroku, Azure) that has since been deleted or "
        "unclaimed. An attacker can register that service and serve malicious content "
        "under your trusted domain, steal cookies, or conduct phishing."
    )

    dead_subs_list = [s for s in subdomains if not s.get("is_alive", True)]
    if dead_subs_list:
        pdf.sub_title(f"Unresolvable Subdomains ({len(dead_subs_list)}) - Require Investigation")
        pdf.body(
            "The following subdomains exist in DNS but did not respond during scanning. "
            "They should be investigated for dangling CNAME records pointing to unclaimed "
            "third-party services. NOTE: These are NOT confirmed takeover vulnerabilities "
            "- manual CNAME verification is required."
        )
        d_rows = [[str(s.get("subdomain", ""))[:48],
                   _get_subdomain_ip(s)[:16],
                   "Verify CNAME target"]
                  for s in dead_subs_list[:25]]
        pdf.table(["Subdomain", "IP", "Action"], d_rows, [85, 38, 67])
        if len(dead_subs_list) > 25:
            pdf.body(f"... and {len(dead_subs_list) - 25} more unresolvable subdomains.")
    else:
        pdf.body(
            "All discovered subdomains are currently resolving and responsive. "
            "No dangling DNS indicators detected at this time."
        )

    # ══════════════════════════════════════════════════════════════════
    # 7. PORT & SERVICE ANALYSIS
    # ══════════════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.chapter_title("7. Port & Service Analysis")

    pdf.body(
        f"{len(ports)} open ports were discovered across all hosts. "
        f"Every open port is an entry point into the infrastructure."
    )

    # Dangerous ports first
    dangerous_found = [p for p in ports if p.get("port") in DANGEROUS_PORTS]
    if dangerous_found:
        pdf.sub_title(f"Dangerous / Elevated Risk Ports ({len(dangerous_found)})")
        for p in dangerous_found[:10]:
            port_num = p.get("port", 0)
            desc     = DANGEROUS_PORTS.get(port_num, "Unknown Service")
            color    = (192, 57, 43) if port_num in HIGH_RISK_PORTS else (211, 84, 0)
            pdf.alert_box(
                f"PORT {port_num} ({desc}) - {p.get('host', 'N/A')}",
                f"Service:     {p.get('service', desc)}\n"
                f"Risk:        This port/service should not be exposed to the internet\n"
                f"             unless strictly required and hardened.\n"
                f"Remediation: Restrict access with firewall rules to trusted IPs only,\n"
                f"             or disable if not required.",
                color=color
            )

    # Full port table
    pdf.sub_title("Port Inventory")
    port_rows = []
    for p in ports:
        port_num = p.get("port", 0)
        risk = "HIGH RISK" if port_num in HIGH_RISK_PORTS else (
               "Elevated"  if port_num in DANGEROUS_PORTS else "Standard")
        port_rows.append([
            str(p.get("host", ""))[:38],
            str(port_num),
            str(p.get("service", ""))[:14],
            risk,
        ])
    if port_rows:
        pdf.table(["Host", "Port", "Service", "Risk"],
                  port_rows, [85, 22, 42, 41])

    # ══════════════════════════════════════════════════════════════════
    # 8. WEB ASSET ANALYSIS
    # ══════════════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.chapter_title("8. Web Asset Analysis")

    pdf.body(f"{len(http_assets)} HTTP assets were discovered and probed.")

    if count_429 > 0:
        pdf.alert_box(
            f"RATE LIMITING: {count_429} of {len(http_assets)} hosts returned HTTP 429",
            f"The target is actively rate limiting the scanner. Results for {count_429} "
            f"hosts may be incomplete. A slower scan rate is recommended.",
            color=(243, 156, 18)
        )

    # Response code distribution
    pdf.sub_title("8.1 Response Code Distribution")
    status_dist = {}
    for a in http_assets:
        code = str(a.get("status_code", "Unknown"))
        status_dist[code] = status_dist.get(code, 0) + 1

    if status_dist:
        meanings = {
            "200": "OK - Serving content",
            "301": "Redirect (Permanent)",
            "302": "Redirect (Temporary)",
            "307": "Redirect (Temporary)",
            "308": "Redirect (Permanent)",
            "401": "Authentication Required",
            "403": "Forbidden",
            "404": "Not Found",
            "409": "Conflict",
            "429": "Rate Limited",
            "500": "Server Error",
            "502": "Bad Gateway",
            "503": "Service Unavailable",
        }
        s_rows = [[code, meanings.get(code, ""), str(cnt)]
                  for code, cnt in sorted(status_dist.items())]
        pdf.table(["Status Code", "Meaning", "Count"], s_rows, [35, 105, 50])

    # Assets table
    pdf.sub_title("8.2 HTTP Assets")
    if http_assets:
        asset_rows = []
        for a in http_assets:
            asset_rows.append([
                str(a.get("url", ""))[:58],
                str(a.get("status_code", "")),
                str(a.get("title", ""))[:28],
            ])
        pdf.table(["URL", "Status", "Title"], asset_rows, [108, 22, 60])

    # Security headers
    pdf.sub_title("8.3 Security Headers Analysis")
    pdf.body(
        "Security headers instruct the browser how to handle content and protect users. "
        "Missing headers are quick wins — often fixable with a single line of server config."
    )
    if raw_sec_headers:
        hdr_rows = []
        for h in raw_sec_headers[:20]:
            hdr_rows.append([
                str(h.get("host", ""))[:48],
                str(h.get("missing", ""))[:80],
            ])
        pdf.table(["Host", "Missing Security Headers"], hdr_rows, [55, 135])
        if len(raw_sec_headers) > 20:
            pdf.body(f"... and {len(raw_sec_headers) - 20} more hosts with missing headers.")

        # Aggregate summary
        pdf.sub_title("Header Coverage Summary")
        header_miss_counts = {}
        for h in raw_sec_headers:
            for hdr in str(h.get("missing", "")).split(", "):
                hdr = hdr.strip()
                if hdr:
                    header_miss_counts[hdr] = header_miss_counts.get(hdr, 0) + 1
        if header_miss_counts:
            h_rows = []
            for hdr_label, miss_count in sorted(header_miss_counts.items(),
                                                key=lambda x: x[1], reverse=True):
                # Find risk level for this header
                risk_lvl = next(
                    (risk for _, label, risk, _ in SECURITY_HEADERS_LIST
                     if label == hdr_label), "Low"
                )
                h_rows.append([hdr_label, str(miss_count), risk_lvl])
            pdf.table(["Missing Header", "Hosts Affected", "Risk Level"],
                      h_rows, [80, 60, 50])
    else:
        pdf.body(
            "Security headers data not available. To enable this analysis, ensure "
            "HTTPX stores response headers in the http_assets collection, or provide "
            "a security_headers field in the report data."
        )

    # ══════════════════════════════════════════════════════════════════
    # 9. SSL/TLS ANALYSIS
    # ══════════════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.chapter_title("9. SSL/TLS Analysis")

    pdf.body(
        "TLS configuration is a direct compliance requirement for PCI-DSS v4.0, SOC 2, "
        "and ISO 27001. TLS 1.0 and 1.1 are deprecated and prohibited under PCI-DSS v4.0."
    )

    pdf.sub_title("HTTPS Coverage")
    if http_assets:
        https_pct = round(https_count / len(http_assets) * 100, 1) if http_assets else 0
        pdf.stat_row("HTTPS Assets",           https_count)
        pdf.stat_row("HTTP-Only Assets",        http_only, warn=http_only > 0)
        pdf.stat_row("HTTPS Coverage",          f"{https_pct}%",
                     warn=https_pct < 100)

    # Censys TLS details if available
    censys_svcs = censys_data.get("services", []) if censys_data else []
    if censys_svcs:
        pdf.sub_title("TLS Details (from Censys)")
        tls_rows = []
        for s in censys_svcs[:20]:
            tls_rows.append([
                str(s.get("ip", s.get("hostname", "")))[:22],
                str(s.get("port", "")),
                str(s.get("tls_version", "N/A")),
                str(s.get("certificate_cn", s.get("ssl_subject", "")))[:32],
            ])
        pdf.table(["IP / Host", "Port", "TLS Version", "Certificate CN"],
                  tls_rows, [50, 20, 40, 80])
    else:
        pdf.body(
            "Detailed TLS version and cipher suite analysis requires Censys API integration. "
            "Configure CENSYS_PAT to enable full TLS analysis including weak cipher detection, "
            "certificate expiry, and protocol version auditing."
        )

    # ══════════════════════════════════════════════════════════════════
    # 10. TECHNOLOGY FINGERPRINTING
    # ══════════════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.chapter_title("10. Technology Fingerprinting")

    if technologies:
        pdf.body(
            f"{len(technologies)} unique technologies were detected across web assets. "
            f"Outdated or EOL technologies may harbor unpatched vulnerabilities."
        )
        tech_rows = []
        for t in technologies:
            name_lower = str(t[0]).lower()
            note = next(
                (v for k, v in OUTDATED_TECH_FLAGS.items() if k in name_lower),
                ""
            )
            tech_rows.append([str(t[0])[:35], str(t[1]), note])
        pdf.table(["Technology", "Count", "Risk Note / Action"],
                  tech_rows, [68, 18, 104])
    else:
        pdf.body("No technologies were fingerprinted during this assessment.")

    # ══════════════════════════════════════════════════════════════════
    # 11. VULNERABILITY FINDINGS
    # ══════════════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.chapter_title("11. Vulnerability Findings")

    pdf.sub_title("11.1 Vulnerability Statistics")
    pdf.table(
        ["Severity", "Count", "SLA", "Action Required"],
        [
            ["CRITICAL", str(crit),       "24-48 hrs", "Immediate executive attention"],
            ["HIGH",     str(high),       "7 days",    "Urgent patch/remediation"],
            ["MEDIUM",   str(med),        "30 days",   "Planned remediation"],
            ["LOW",      str(low),        "90 days",   "Scheduled maintenance"],
            ["INFO",     str(info_count), "-",         "Informational only"],
        ],
        [30, 20, 30, 110]
    )

    if kev_count > 0:
        pdf.alert_box(
            f"CISA KEV ALERT: {kev_count} actively exploited vulnerabilities detected",
            "These CVEs are confirmed actively exploited by real threat actors.\n"
            "Immediate patching is required per CISA Binding Operational Directive 22-01.",
            color=(192, 57, 43)
        )

    # Critical & High finding sheets
    pdf.sub_title("11.2 Critical & High Findings")
    fnum = 1
    for sev in ["critical", "high"]:
        for vuln in vulns_by_sev.get(sev, []):
            pdf.finding_sheet(vuln, fnum, sev.upper())
            fnum += 1
    if fnum == 1:
        pdf.body("No critical or high-severity vulnerabilities detected in this scan.")

    # Medium, Low, Info tables
    for sev_label, sev_key in [("MEDIUM", "medium"), ("LOW", "low"), ("INFO", "info")]:
        sevs = vulns_by_sev.get(sev_key, [])
        if sevs:
            pdf.sub_title(f"11.3 {sev_label} Findings ({len(sevs)})")
            v_rows = []
            for v in sevs:
                rem_summary = ""
                rem = v.get("remediation", {})
                if isinstance(rem, dict):
                    rem_summary = rem.get("summary", "")
                elif isinstance(rem, str):
                    rem_summary = rem
                v_rows.append([
                    str(v.get("name", v.get("template_id", "?")))[:42],
                    str(v.get("host", ""))[:32],
                    v.get("cve_id", "-"),
                    str(rem_summary)[:38],
                ])
            pdf.table(["Finding", "Host", "CVE", "Remediation Summary"],
                      v_rows, [60, 42, 25, 63])

    # ══════════════════════════════════════════════════════════════════
    # 12. THREAT INTELLIGENCE CONTEXT
    # ══════════════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.chapter_title("12. Threat Intelligence Context")

    pdf.sub_title("12.1 CVE Threat Context")
    if kev_count > 0:
        pdf.body(
            f"{kev_count} CVEs found in this scan are listed in CISA's Known Exploited "
            f"Vulnerabilities catalog. These are actively used by threat actors and "
            f"ransomware groups in real-world attacks. Treat these as top priority."
        )
    if avg_epss is not None and avg_epss > 0.5:
        pdf.body(
            f"The average EPSS score of {avg_epss} indicates HIGH probability of "
            f"exploitation within the next 30 days. EPSS scores above 0.5 place "
            f"vulnerabilities in the top percentile of exploitation likelihood."
        )
    elif avg_epss is not None and avg_epss > 0:
        pdf.body(
            f"Average EPSS score: {avg_epss}. EPSS (Exploit Prediction Scoring System) "
            f"measures the likelihood of exploitation within 30 days "
            f"(0.0 = unlikely, 1.0 = near-certain)."
        )
    elif total_vulns > 0:
        pdf.body(
            "No EPSS data available for the detected vulnerabilities. This is typically "
            "because no CVE IDs were assigned (e.g., configuration findings, misconfigurations)."
        )
    else:
        pdf.body("No vulnerabilities detected. No CVE threat intelligence analysis required.")

    pdf.sub_title("12.2 Breach Intelligence Correlation")
    if breached > 0:
        pdf.body(
            f"{breached} employee emails ({breach_rate}%) were found in known data breaches. "
            f"If password reuse exists, attackers can use these credentials for account "
            f"takeover on VPN portals, admin panels, SaaS platforms, and cloud services. "
            f"{f'{pwd_leaks} accounts had plaintext or cracked passwords exposed.' if pwd_leaks else ''}"
        )
    else:
        pdf.body("No employee credentials found in known breach databases.")

    # ══════════════════════════════════════════════════════════════════
    # 13. EMAIL & PEOPLE INTELLIGENCE
    # ══════════════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.chapter_title("13. Email & People Intelligence")

    if total_emails > 0:
        pdf.sub_title("13.1 Email Exposure Summary")
        pdf.table(
            ["Metric", "Count"],
            [
                ["Total Emails Discovered", str(total_emails)],
                ["Breached",               str(breached)],
                ["Clean",                  str(email_stats.get("clean", 0))],
                ["Unchecked",              str(email_stats.get("unchecked", 0))],
                ["Password Leaks",         str(pwd_leaks)],
                ["Breach Rate",            f"{breach_rate}%"],
            ],
            [120, 70]
        )

        pdf.sub_title("13.2 Discovered Emails")
        email_rows = []
        for e in emails:
            email_rows.append([
                str(e.get("email", ""))[:38],
                ", ".join(e.get("sources", []))[:18],
                "Yes" if e.get("breach_status") == "breached" else "No",
                "Yes" if e.get("password_leaked") else "No",
            ])
        if email_rows:
            pdf.table(["Email", "Source", "Breached", "Pwd Leaked"],
                      email_rows, [70, 33, 37, 50])

        # Breach details
        breached_emails = [e for e in emails if e.get("breach_status") == "breached"]
        if breached_emails:
            pdf.sub_title(f"13.3 Breach Details ({len(breached_emails)} emails)")
            for e in breached_emails[:20]:
                raw_breaches   = e.get("breaches", [])
                breach_names   = [_clean_breach_name(b) for b in raw_breaches[:5]]
                # Deduplicate
                seen = set()
                unique_names = []
                for bn in breach_names:
                    if bn not in seen:
                        seen.add(bn)
                        unique_names.append(bn)
                breach_str = ", ".join(unique_names) if unique_names else "Unknown"
                color = (192, 57, 43) if e.get("password_leaked") else (211, 84, 0)
                pdf.alert_box(
                    f"BREACH - {e.get('email', 'unknown')}",
                    f"Found In:    {breach_str}\n"
                    f"Pwd Leaked:  {'Yes - immediate password reset required' if e.get('password_leaked') else 'No'}\n"
                    f"Remediation: Force password reset. Enable MFA immediately.\n"
                    f"             Audit recent login activity for this account.",
                    color=color
                )
            if len(breached_emails) > 20:
                pdf.body(
                    f"... and {len(breached_emails) - 20} more breached emails. "
                    f"All require password resets and MFA enforcement."
                )
    else:
        pdf.body("No email addresses were discovered during this assessment.")

    # ══════════════════════════════════════════════════════════════════
    # 14. RISK SCORE BREAKDOWN
    # ══════════════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.chapter_title("14. Risk Score - Transparent Breakdown")

    pdf.body(
        "The risk score is a weighted composite of multiple security factors. "
        "This section shows exactly how the score was calculated to support "
        "audit transparency and reproducibility."
    )

    pdf.sub_title("14.1 Scoring Components")
    breach_contrib = ("+15" if breached > 10 else
                      "+10" if breached > 5 else
                      "+5"  if breached > 0 else "0")
    pdf.table(
        ["Factor", "Value", "Contribution"],
        [
            ["Critical CVEs",       str(crit),         f"{crit * 40} pts (x40 each)"],
            ["High CVEs",           str(high),         f"{high * 25} pts (x25 each)"],
            ["Medium CVEs",         str(med),          f"{med * 10} pts (x10 each)"],
            ["Low CVEs",            str(low),          f"{low * 3} pts (x3 each)"],
            ["Info findings",       str(info_count),   f"{info_count} pts (x1 each)"],
            ["Subdomains > 50",     str(subs_count),   "+10" if subs_count > 50 else "0"],
            ["Ports > 100",         str(len(ports)),   "+10" if len(ports) > 100 else "0"],
            ["HTTP Assets > 20",    str(assets_count), "+5"  if assets_count > 20 else "0"],
            ["Breached Emails",     str(breached),     breach_contrib],
        ],
        [65, 35, 90]
    )
    pdf.bold_body(f"Total (capped at 100): {risk_score}/100 - {risk_level}")

    pdf.sub_title("14.2 Key Risk Drivers")
    drivers = []
    if crit > 0:
        drivers.append(f"{crit} Critical CVEs — contributing {crit * 40} points to score")
    if high > 0:
        drivers.append(f"{high} High CVEs — contributing {high * 25} points to score")
    if kev_count > 0:
        drivers.append(f"{kev_count} actively exploited vulnerabilities confirmed in CISA KEV")
    if dangerous > 0:
        drivers.append(f"{dangerous} dangerous ports exposed (FTP/Telnet/RDP/Redis/etc)")
    if breached > 5:
        drivers.append(
            f"{breached} employee emails in breach databases ({breach_rate}%)"
            f"{f' — {pwd_leaks} with password leaks' if pwd_leaks else ''}"
        )
    if http_only > 0:
        drivers.append(f"{http_only} assets serving unencrypted HTTP traffic")
    if drivers:
        pdf.bullets(drivers)
    else:
        pdf.body(
            "No dominant risk factors. Score is driven by attack surface exposure "
            "metrics (subdomain count, port count, asset count) and minor findings."
        )

    # ══════════════════════════════════════════════════════════════════
    # 15. REMEDIATION ROADMAP
    # ══════════════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.chapter_title("15. Remediation Roadmap")

    immediate   = [r for r in recommendations if r.get("timeframe") in ["24 hours", "48 hours"]]
    short_term  = [r for r in recommendations if r.get("timeframe") == "7 days"]
    medium_term = [r for r in recommendations if r.get("timeframe") == "30 days"]
    long_term   = [r for r in recommendations if r.get("timeframe") in ["90 days", "Ongoing"]]

    def _rec_table(recs, title):
        if recs:
            pdf.sub_title(title)
            rows = [
                [str(i + 1),
                 r.get("action", "No action specified"),
                 r.get("compliance", "-")]
                for i, r in enumerate(recs)
            ]
            pdf.table(["#", "Action", "Compliance Controls"], rows, [10, 115, 65])

    _rec_table(immediate,   "Immediate - 0 to 48 Hours (Stop the Bleeding)")
    _rec_table(short_term,  "Short Term - 1 to 7 Days (Urgent)")
    _rec_table(medium_term, "Medium Term - 8 to 30 Days (Planned)")
    _rec_table(long_term,   "Long Term - 31 to 90 Days (Structural)")

    # Fallback if recommendations exist but have no timeframe field
    if recommendations and not any([immediate, short_term, medium_term, long_term]):
        _rec_table(recommendations, "Recommended Actions")

    if not recommendations:
        pdf.body(
            "No remediation actions generated for this scan. "
            "Continue regular monitoring and periodic reassessment."
        )

    # ══════════════════════════════════════════════════════════════════
    # 16. CHANGE ANALYSIS (DELTA)
    # ══════════════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.chapter_title("16. Change Analysis (Delta)")

    if changes:
        pdf.body(f"{len(changes)} changes were detected since the last scan.")

        # Change type counts
        type_counts = {}
        for c in changes:
            ct = c.get("change_type", "unknown")
            type_counts[ct] = type_counts.get(ct, 0) + 1

        # Warn if suspiciously one-sided
        if type_counts:
            dominant_type = max(type_counts, key=type_counts.get)
            dominant_pct  = round(type_counts[dominant_type] / len(changes) * 100)
            if dominant_pct > 80 and len(changes) > 10:
                pdf.alert_box(
                    f"CHANGE PATTERN: {dominant_pct}% of changes are '{dominant_type}'",
                    f"This may indicate a scan coverage gap rather than real infrastructure changes.\n"
                    f"Rate limiting was detected ({count_429} HTTP 429s), which may cause services\n"
                    f"to appear closed when they are actually still running.\n"
                    f"Recommendation: Run a slower rescan to verify these closures.",
                    color=(243, 156, 18)
                )

        # Summary table
        pdf.sub_title("Change Type Summary")
        ct_rows = [[ct, str(cnt)]
                   for ct, cnt in sorted(type_counts.items(),
                                         key=lambda x: x[1], reverse=True)]
        pdf.table(["Change Type", "Count"], ct_rows, [120, 70])

        # Top 10 changes in body — full list goes to appendix
        pdf.sub_title("Recent Changes (Top 10)")
        ch_rows = []
        for c in changes[:10]:
            ch_rows.append([
                str(c.get("change_type", ""))[:20],
                _flatten_details(c.get("details", ""))[:58],
                str(c.get("detected_at", ""))[:19],
            ])
        pdf.table(["Type", "Details", "Detected At"], ch_rows, [38, 102, 50])

        if len(changes) > 10:
            pdf.body(
                f"... and {len(changes) - 10} more changes not shown here. "
                f"See Appendix D for the complete change log."
            )
    else:
        pdf.body(
            "No change data available. Run multiple scans over time to "
            "enable delta analysis and track infrastructure changes."
        )

    # ══════════════════════════════════════════════════════════════════
    # 17. APPENDIX
    # ══════════════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.chapter_title("17. Appendix")

    # Appendix A: Scan Log
    pdf.sub_title("Appendix A - Scan Execution Log")
    if scan_info:
        pdf.kv_line("Scan ID:",   str(scan_info.get("_id", "N/A"))[:24])
        pdf.kv_line("Status:",    scan_info.get("status", "N/A"))
        pdf.kv_line("Started:",   str(scan_info.get("started_at", "N/A"))[:19])
        pdf.kv_line("Completed:", str(scan_info.get("completed_at", "N/A"))[:19])
        phases = scan_info.get("phases", {})
        if phases:
            pdf.ln(2)
            pdf.bold_body("Phase Execution:")
            for pname, pdata in phases.items():
                if isinstance(pdata, dict):
                    status  = pdata.get("status", "N/A")
                    results = pdata.get("results_count", "")
                    suffix  = f" ({results} results)" if results else ""
                    pdf.kv_line(f"  {pname}:", f"{status}{suffix}")
                else:
                    pdf.kv_line(f"  {pname}:", str(pdata))
    else:
        pdf.body("No scan execution data available.")

    # Appendix B: Data Sources
    pdf.sub_title("Appendix B - Data Sources Status")
    ds_rows = [
        ["Shodan API",  "Available" if shodan_data.get("hosts")
                        else "Not configured or no data returned"],
        ["Censys API",  "Available" if censys_data and censys_data.get("hosts")
                        else "Not configured or no data returned"],
        ["WHOIS",       "Available" if whois_data and whois_data.get("registrar")
                        else "Not configured or no data returned"],
        ["LeakCheck",   "Available" if (breached > 0 or total_emails > 0)
                        else "Not configured or no data returned"],
        ["Sec Headers", "Available" if raw_sec_headers
                        else "Not available - headers not stored in scan data"],
        ["Censys TLS",  "Available" if censys_data and censys_data.get("services")
                        else "Not configured - TLS analysis unavailable"],
    ]
    pdf.table(["Source", "Status"], ds_rows, [55, 135])

    # Appendix C: Glossary
    pdf.sub_title("Appendix C - Glossary")
    glossary = [
        ["EPSS",     "Exploit Prediction Scoring System - probability of exploitation in 30 days (0-1)"],
        ["KEV",      "Known Exploited Vulnerabilities - CISA catalog of actively exploited CVEs"],
        ["CVSS",     "Common Vulnerability Scoring System - severity rating 0.0 to 10.0"],
        ["CVE",      "Common Vulnerabilities and Exposures - unique vulnerability identifier"],
        ["CNAME",    "Canonical Name DNS record - alias pointing to another domain"],
        ["TLS",      "Transport Layer Security - encryption protocol for web traffic"],
        ["HSTS",     "HTTP Strict Transport Security - forces HTTPS connections"],
        ["CSP",      "Content Security Policy - prevents XSS by restricting content sources"],
        ["OSINT",    "Open Source Intelligence - information gathered from public sources"],
        ["SOC 2",    "Service Organization Control 2 - security audit framework"],
        ["PCI-DSS",  "Payment Card Industry Data Security Standard"],
        ["ISO 27001","International information security management standard"],
        ["OWASP",    "Open Web Application Security Project - web security guidelines"],
        ["WAF",      "Web Application Firewall - filters malicious HTTP traffic"],
        ["ASN",      "Autonomous System Number - identifies a network operator/ISP"],
    ]
    pdf.table(["Term", "Definition"], glossary, [28, 162])

    # Appendix D: Full Change Log (if changes exist and were truncated)
    if changes and len(changes) > 10:
        pdf.sub_title("Appendix D - Full Change Log")
        pdf.body(f"Complete list of all {len(changes)} detected changes:")
        all_ch_rows = []
        for c in changes:
            all_ch_rows.append([
                str(c.get("change_type", ""))[:20],
                _flatten_details(c.get("details", ""))[:58],
                str(c.get("detected_at", ""))[:19],
            ])
        pdf.table(["Type", "Details", "Detected At"], all_ch_rows, [38, 102, 50])

    # ── Save ─────────────────────────────────────────────────────────
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename  = f"report_{safe_domain}_{timestamp}.pdf"
    filepath  = os.path.join("generated_reports", filename)
    pdf.output(filepath)
    print(f"[PDF] Domain report saved: {filepath}")
    return filepath


# ═══════════════════════════════════════════════════════════════════════════
#  OVERALL ORGANIZATION REPORT
# ═══════════════════════════════════════════════════════════════════════════

def _generate_overall_pdf(report_data):
    os.makedirs("generated_reports", exist_ok=True)

    pdf = EASMReport()
    pdf.alias_nb_pages()

    org_stats      = report_data.get("organization_stats", {})
    domains_stats  = report_data.get("domains_stats", [])
    overall_risk   = org_stats.get("average_risk_score", 0)
    risk_level     = _risk_label(overall_risk)
    report_id      = hashlib.md5(
        f"org{datetime.now().isoformat()}".encode()
    ).hexdigest()[:12].upper()

    total_crit   = org_stats.get("total_critical", 0)
    total_high   = org_stats.get("total_high", 0)
    total_med    = org_stats.get("total_medium", 0)
    total_low    = org_stats.get("total_low", 0)
    total_domains = len(domains_stats)

    sorted_domains = sorted(domains_stats,
                            key=lambda x: x.get("risk_score", 0),
                            reverse=True)

    # ── COVER ────────────────────────────────────────────────────────
    pdf.add_page()
    pdf.ln(15)

    pdf.set_font("Helvetica", "B", 28)
    pdf.set_text_color(44, 62, 80)
    pdf.cell(0, 14, "EASM AEGIS", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 13)
    pdf.cell(0, 8, "Organization Portfolio Risk Report",
             align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)
    pdf.ln(8)

    pdf.set_font("Helvetica", "B", 18)
    pdf.set_text_color(41, 128, 185)
    pdf.cell(0, 12, _safe(f"{total_domains} Monitored Domains"),
             align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)
    pdf.ln(8)

    r, g, b = _risk_color(overall_risk)
    pdf.set_fill_color(r, g, b)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 30)
    x_center = (210 - 60) / 2
    pdf.set_xy(x_center, pdf.get_y())
    pdf.cell(60, 18, f"{overall_risk}/100", align="C", fill=True,
             new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(r, g, b)
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 8, f"Portfolio Risk: {risk_level}",
             align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)
    pdf.ln(10)

    pdf.set_font("Helvetica", "", 10)
    for line in [
        f"Report ID:    RPT-{report_id}",
        f"Generated:    {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        f"Audience:     CISO & Executive Management",
        f"Classification: CONFIDENTIAL",
    ]:
        pdf.cell(0, 6, _safe(line), align="C", new_x="LMARGIN", new_y="NEXT")

    pdf.ln(5)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(130, 130, 130)
    pdf.cell(0, 5, "This document contains sensitive security findings. "
             "Unauthorized distribution is prohibited.",
             align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)

    pdf.insert_toc_placeholder(render_toc, pages=1)

    # ── 1. PORTFOLIO EXECUTIVE SUMMARY ───────────────────────────────
    pdf.add_page()
    pdf.chapter_title("1. Portfolio Executive Summary")

    pdf.body(
        f"This report aggregates the security posture across {total_domains} monitored "
        f"domains. A total of {total_crit} critical and {total_high} high-severity "
        f"vulnerabilities were identified across the portfolio. "
        f"The average portfolio risk score is {overall_risk}/100 ({risk_level})."
    )

    pdf.sub_title("Organization-Wide Vulnerability Summary")
    pdf.table(
        ["Severity", "Total Across All Domains"],
        [
            ["Critical", str(total_crit)],
            ["High",     str(total_high)],
            ["Medium",   str(total_med)],
            ["Low",      str(total_low)],
        ],
        [80, 110]
    )

    if sorted_domains:
        pdf.sub_title("Top 5 Domains Requiring Immediate Attention")
        top_rows = [
            [str(d.get("domain", ""))[:35],
             f"{d.get('risk_score', 0)}/100",
             _risk_label(d.get("risk_score", 0)),
             str(d.get("critical_vulns", 0)),
             str(d.get("high_vulns", 0)),
             str(d.get("total_vulns", 0))]
            for d in sorted_domains[:5]
        ]
        pdf.table(
            ["Domain", "Score", "Level", "Crit", "High", "Total"],
            top_rows,
            [55, 22, 28, 18, 18, 49]
        )

    # ── 2. DOMAIN RISK COMPARISON ────────────────────────────────────
    pdf.add_page()
    pdf.chapter_title("2. Domain Risk Comparison")

    if sorted_domains:
        all_rows = [
            [str(d.get("domain", ""))[:32],
             f"{d.get('risk_score', 0)}/100",
             _risk_label(d.get("risk_score", 0)),
             str(d.get("critical_vulns", 0)),
             str(d.get("high_vulns", 0)),
             str(d.get("medium_vulns", 0)),
             str(d.get("total_vulns", 0))]
            for d in sorted_domains
        ]
        pdf.table(
            ["Domain", "Score", "Level", "Crit", "High", "Med", "Total"],
            all_rows,
            [52, 20, 26, 16, 16, 16, 44]
        )

    # Risk gauge bars
    pdf.sub_title("Portfolio Risk Gauge")
    pdf.set_font("Courier", "", 8)
    for d in sorted_domains[:15]:
        score   = d.get("risk_score", 0)
        bar_len = int(score / 100 * 28)
        bar     = "#" * bar_len + "-" * (28 - bar_len)
        label   = _risk_label(score)
        domain_str = str(d.get("domain", ""))[:22]
        pdf.cell(0, 5,
                 _safe(f"  {domain_str:<24} [{bar}] {score:>3}  {label}"),
                 new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    # ── 3. PORTFOLIO RECOMMENDATIONS ────────────────────────────────
    pdf.add_page()
    pdf.chapter_title("3. Portfolio-Level Recommendations")

    pdf.body(
        "The following recommendations apply across the organization based on "
        "the aggregated findings. Address systemic issues that affect multiple "
        "domains before focusing on individual domain hardening."
    )

    systemic = []
    if total_crit > 0:
        systemic.append(
            f"Immediately patch all {total_crit} critical vulnerabilities across the portfolio. "
            f"Assign domain owners and track remediation status centrally."
        )
    if total_high > 0:
        systemic.append(
            f"Schedule urgent remediation of {total_high} high-severity vulnerabilities "
            f"within 7 days per standard SLA."
        )

    # Domains with critical issues
    crit_domains = [d.get("domain", "") for d in sorted_domains
                    if d.get("critical_vulns", 0) > 0]
    if crit_domains:
        systemic.append(
            f"Domains with critical findings requiring immediate owner escalation: "
            f"{', '.join(crit_domains[:5])}"
            f"{'...' if len(crit_domains) > 5 else ''}."
        )

    if systemic:
        pdf.bullets(systemic)
    else:
        pdf.body("No critical systemic issues identified across the portfolio.")

    # ── Save ─────────────────────────────────────────────────────────
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename  = f"org_report_{timestamp}.pdf"
    filepath  = os.path.join("generated_reports", filename)
    pdf.output(filepath)
    print(f"[PDF] Org report saved: {filepath}")
    return filepath