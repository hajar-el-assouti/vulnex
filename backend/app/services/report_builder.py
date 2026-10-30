"""Builds the PDF/HTML pentest report content.

No database code: plain dicts/dataclasses in, bytes/str out. Database
access stays in app/services/reports.py.

Sections: cover, authorized scope, executive summary, risk summary,
modules run, methodology, findings list, technical description and
redacted evidence per finding, remediation, test limitations,
conclusion. Every number comes from the `context` built from stored
data.

## Confidence

A finding's `confidence` (low/medium/high/confirmed) is the engine's
own value, never changed here. The report explains what "confirmed"
means and doesn't mean (see _CONFIDENCE_EXPLAINER).

## Passive vs. active testing

`context["active_testing_performed"]` is True only if the scan really
ran `active_web_testing` (from the ScanModuleRun rows). The
limitations section says clearly if only passive checks were done.
"""

from __future__ import annotations

import html as html_escape_module
from dataclasses import dataclass
from datetime import datetime
from io import BytesIO
from typing import Any

import jinja2
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_SEVERITY_HEX = {
    "critical": "#7f1d1d",
    "high": "#b91c1c",
    "medium": "#b45309",
    "low": "#1d4ed8",
    "info": "#4b5563",
}

_CONFIDENCE_EXPLAINER = (
    "Confidence levels in this report describe how certain the scanning engine itself is, "
    "not a legal or contractual certification. 'Low'/'Medium' findings are indicators that "
    "warrant manual verification before remediation effort is spent. 'High' findings are "
    "backed by strong, directly-observed evidence. 'Confirmed' is reserved for findings "
    "whose evidence leaves no reasonable alternative explanation -- it is never assigned "
    "automatically, and this report never upgrades a lower confidence to 'Confirmed' on its "
    "own initiative."
)


@dataclass
class ReportFindingView:
    title: str
    severity: str
    confidence: str
    category: str
    description: str | None
    affected_url: str | None
    cwe_id: str | None
    evidence: dict[str, Any]
    remediation: str | None


@dataclass
class ReportModuleRunView:
    slug: str
    name: str
    description: str | None
    status: str


@dataclass
class ReportContext:
    report_id: str
    generated_at: datetime
    generated_by_email: str
    scan_id: str
    scan_status: str
    scan_started_at: datetime | None
    scan_finished_at: datetime | None
    target_name: str
    target_base_url: str
    target_authorization_reference: str | None
    target_authorized_at: datetime | None
    modules: list[ReportModuleRunView]
    findings: list[ReportFindingView]
    active_testing_performed: bool

    def severity_counts(self) -> dict[str, int]:
        counts = {s: 0 for s in _SEVERITY_ORDER}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def risk_rating(self) -> str:
        """A conservative, non-alarmist synthesis ("sans
        surestimation") -- driven only by counts that are actually
        non-zero, never by a weighted score that could overstate a
        single low-confidence finding."""
        counts = self.severity_counts()
        if counts["critical"] > 0:
            return "Critical"
        if counts["high"] > 0:
            return "High"
        if counts["medium"] > 0:
            return "Medium"
        if counts["low"] > 0:
            return "Low"
        return "Informational"

    def executive_summary(self) -> str:
        total = len(self.findings)
        counts = self.severity_counts()
        if total == 0:
            return (
                "No findings were recorded for this scan. This means the modules that ran "
                "did not flag anything meeting their own reporting threshold -- it is not a "
                "certification that the target is free of vulnerabilities, only that nothing "
                "was found by the specific checks this scan ran."
            )
        parts = [f"{counts[s]} {s}" for s in _SEVERITY_ORDER if counts[s] > 0]
        return (
            f"This scan recorded {total} finding(s) across the modules listed below: "
            f"{', '.join(parts)}. See the findings section for full technical detail on each one."
        )

    def limitations_statement(self) -> str:
        if self.active_testing_performed:
            return (
                "This scan included ACTIVE testing (the active_web_testing module): real test "
                "requests (reflected-XSS markers, differential SQL-injection probes, HTTP "
                "parameter testing, active API-security checks) were sent to the authorized "
                "target. Active testing is still conservative by design -- it never performs a "
                "non-idempotent (state-changing) request and never attempts exploitation beyond "
                "what is needed to observe an indicator."
            )
        return (
            "This scan performed ONLY PASSIVE testing: every module involved reads information "
            "the target already serves (HTTP responses, headers, DNS records, TLS "
            "configuration, ...) without sending any crafted test payload. No active "
            "vulnerability probing (XSS, SQL injection, or similar) was attempted against the "
            "target during this scan."
        )


def _esc(value: str | None) -> str:
    return html_escape_module.escape(value) if value else ""


def _redacted_evidence_lines(evidence: dict[str, Any]) -> list[str]:
    """Evidence is already redacted at persistence time (every
    engine's own redact_secrets() call, upstream of this report --
    see app/engines/active_web_testing/checks/*.py and
    app/engines/web_vuln/checks/*.py) -- this just formats it for
    display, dropping this module's own internal bookkeeping keys
    (leading underscore) that mean nothing to a report reader."""
    lines = []
    for key, value in sorted(evidence.items()):
        if key.startswith("_"):
            continue
        lines.append(f"{key}: {value}")
    return lines


# ---------------------------------------------------------------------
# PDF (reportlab) -- chosen specifically because it is pure Python, no
# system Cairo/Pango/GTK libraries to add to the Docker image (see
# requirements.txt's own comment).
# ---------------------------------------------------------------------


def render_pdf(ctx: ReportContext) -> bytes:
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        title=f"Pentest Report {ctx.report_id}",
    )
    styles = getSampleStyleSheet()
    h1 = styles["Title"]
    h2 = ParagraphStyle("H2", parent=styles["Heading2"], spaceBefore=14, spaceAfter=6)
    h3 = ParagraphStyle("H3", parent=styles["Heading3"], spaceBefore=10, spaceAfter=4)
    body = styles["BodyText"]
    small = ParagraphStyle("Small", parent=styles["BodyText"], fontSize=8, textColor=colors.grey)

    elements: list[Any] = []

    # --- Cover -----------------------------------------------------
    elements.append(Spacer(1, 4 * cm))
    elements.append(Paragraph("Security Assessment Report", h1))
    elements.append(Spacer(1, 1 * cm))
    elements.append(Paragraph(f"Target: {_esc(ctx.target_name)}", body))
    elements.append(Paragraph(f"Base URL: {_esc(ctx.target_base_url)}", body))
    elements.append(Paragraph(f"Scan ID: {ctx.scan_id}", body))
    elements.append(Paragraph(f"Report generated: {ctx.generated_at.isoformat()}", body))
    elements.append(Paragraph(f"Generated by: {_esc(ctx.generated_by_email)}", body))
    elements.append(Spacer(1, 0.5 * cm))
    auth_ref = ctx.target_authorization_reference or "(not recorded)"
    elements.append(
        Paragraph(
            f"Authorized scope: this target was recorded as authorized for scanning "
            f"(reference: {_esc(auth_ref)}).",
            body,
        )
    )
    elements.append(PageBreak())

    # --- Executive summary -------------------------------------------
    elements.append(Paragraph("Executive Summary", h2))
    elements.append(Paragraph(_esc(ctx.executive_summary()), body))
    elements.append(Paragraph(f"Overall risk synthesis: <b>{ctx.risk_rating()}</b>", body))

    # --- Modules run --------------------------------------------------
    elements.append(Paragraph("Modules Run", h2))
    rows = [["Module", "Status", "Description"]]
    for m in ctx.modules:
        rows.append([m.name, m.status, (m.description or "")[:180]])
    table = Table(rows, colWidths=[4 * cm, 2.5 * cm, 9.5 * cm])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    elements.append(table)

    # --- Methodology --------------------------------------------------
    elements.append(Paragraph("Methodology", h2))
    elements.append(Paragraph(_esc(ctx.limitations_statement()), body))

    # --- Findings -------------------------------------------------------
    elements.append(Paragraph("Findings", h2))
    if not ctx.findings:
        elements.append(Paragraph("No findings were recorded for this scan.", body))
    for finding in ctx.findings:
        sev_hex = _SEVERITY_HEX.get(finding.severity, "#000000")
        elements.append(
            Paragraph(
                f'<font color="{sev_hex}">[{finding.severity.upper()}]</font> {_esc(finding.title)}',
                h3,
            )
        )
        elements.append(
            Paragraph(f"Confidence: {finding.confidence} &nbsp;&nbsp; Category: {_esc(finding.category)}", small)
        )
        if finding.affected_url:
            elements.append(Paragraph(f"Affected URL: {_esc(finding.affected_url)}", small))
        if finding.cwe_id:
            elements.append(Paragraph(f"CWE: {_esc(finding.cwe_id)}", small))
        if finding.description:
            elements.append(Paragraph(_esc(finding.description), body))
        evidence_lines = _redacted_evidence_lines(finding.evidence)
        if evidence_lines:
            elements.append(Paragraph("Evidence:", small))
            for line in evidence_lines:
                elements.append(Paragraph(f"&bull; {_esc(line)}", small))
        if finding.remediation:
            elements.append(Paragraph(f"<b>Remediation:</b> {_esc(finding.remediation)}", body))
        elements.append(Spacer(1, 0.3 * cm))

    # --- Limitations + conclusion --------------------------------------
    elements.append(Paragraph("Test Limitations", h2))
    elements.append(Paragraph(_esc(ctx.limitations_statement()), body))
    elements.append(
        Paragraph(
            "This report reflects only what the listed modules actually observed during this "
            "one scan. It is not a guarantee of completeness, and it is not a substitute for a "
            "manual penetration test.",
            body,
        )
    )

    elements.append(Paragraph("Conclusion", h2))
    elements.append(
        Paragraph(
            _esc(
                f"This assessment recorded {len(ctx.findings)} finding(s) with an overall risk "
                f"synthesis of {ctx.risk_rating()}. " + _CONFIDENCE_EXPLAINER
            ),
            body,
        )
    )

    doc.build(elements)
    return buffer.getvalue()


# ---------------------------------------------------------------------
# HTML -- rendered from the SAME ReportContext as the PDF, so the two
# formats can never drift into disagreeing about a number.
# ---------------------------------------------------------------------

_HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Security Assessment Report {{ ctx.report_id }}</title>
<style>
body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; max-width: 860px; margin: 2rem auto; color: #1f2937; }
h1 { font-size: 1.8rem; }
h2 { border-bottom: 2px solid #1f2937; padding-bottom: 0.25rem; margin-top: 2rem; }
table { width: 100%; border-collapse: collapse; margin: 1rem 0; }
th, td { border: 1px solid #d1d5db; padding: 0.4rem 0.6rem; text-align: left; font-size: 0.9rem; }
th { background: #1f2937; color: white; }
.finding { border: 1px solid #e5e7eb; border-radius: 6px; padding: 1rem; margin: 1rem 0; }
.sev-critical { color: #7f1d1d; font-weight: bold; }
.sev-high { color: #b91c1c; font-weight: bold; }
.sev-medium { color: #b45309; font-weight: bold; }
.sev-low { color: #1d4ed8; font-weight: bold; }
.sev-info { color: #4b5563; font-weight: bold; }
.meta { color: #6b7280; font-size: 0.85rem; }
</style>
</head>
<body>
<h1>Security Assessment Report</h1>
<p><b>Target:</b> {{ ctx.target_name }} ({{ ctx.target_base_url }})<br>
<b>Scan ID:</b> {{ ctx.scan_id }}<br>
<b>Report generated:</b> {{ ctx.generated_at.isoformat() }}<br>
<b>Generated by:</b> {{ ctx.generated_by_email }}<br>
<b>Authorized scope:</b> reference {{ ctx.target_authorization_reference or "(not recorded)" }}</p>

<h2>Executive Summary</h2>
<p>{{ ctx.executive_summary() }}</p>
<p><b>Overall risk synthesis:</b> {{ ctx.risk_rating() }}</p>

<h2>Modules Run</h2>
<table><tr><th>Module</th><th>Status</th><th>Description</th></tr>
{% for m in ctx.modules %}
<tr><td>{{ m.name }}</td><td>{{ m.status }}</td><td>{{ (m.description or "")[:300] }}</td></tr>
{% endfor %}
</table>

<h2>Methodology</h2>
<p>{{ ctx.limitations_statement() }}</p>

<h2>Findings</h2>
{% if not ctx.findings %}
<p>No findings were recorded for this scan.</p>
{% endif %}
{% for finding in ctx.findings %}
<div class="finding">
<p><span class="sev-{{ finding.severity }}">[{{ finding.severity.upper() }}]</span> {{ finding.title }}</p>
<p class="meta">Confidence: {{ finding.confidence }} &middot; Category: {{ finding.category }}
{% if finding.affected_url %}&middot; Affected URL: {{ finding.affected_url }}{% endif %}
{% if finding.cwe_id %}&middot; CWE: {{ finding.cwe_id }}{% endif %}</p>
<p>{{ finding.description }}</p>
{% set evidence_lines = redacted_evidence(finding.evidence) %}
{% if evidence_lines %}
<ul>{% for line in evidence_lines %}<li>{{ line }}</li>{% endfor %}</ul>
{% endif %}
{% if finding.remediation %}<p><b>Remediation:</b> {{ finding.remediation }}</p>{% endif %}
</div>
{% endfor %}

<h2>Test Limitations</h2>
<p>{{ ctx.limitations_statement() }}</p>
<p class="meta">This report reflects only what the listed modules actually observed during
this one scan. It is not a guarantee of completeness, and it is not a substitute for a manual
penetration test.</p>

<h2>Conclusion</h2>
<p>This assessment recorded {{ ctx.findings|length }} finding(s) with an overall risk synthesis of
{{ ctx.risk_rating() }}. {{ confidence_explainer }}</p>
</body>
</html>
"""

_jinja_env = jinja2.Environment(autoescape=True)
_html_report_template = _jinja_env.from_string(_HTML_TEMPLATE)


def render_html(ctx: ReportContext) -> str:
    return _html_report_template.render(
        ctx=ctx,
        redacted_evidence=_redacted_evidence_lines,
        confidence_explainer=_CONFIDENCE_EXPLAINER,
    )
