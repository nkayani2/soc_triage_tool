"""PDF and HTML triage report generation.

Two output formats are supported:

* **PDF** — generated with ``reportlab``.  Designed for sharing with
  management or attaching to tickets.
* **HTML** — generated with plain string templating.  Lightweight and
  viewable in any browser, useful for quick sharing.

Both generators accept a list of :class:`data.alert_loader.Alert`
instances and write the report to ``reports/`` under the project root.
"""

from __future__ import annotations

import datetime as dt
import html
from pathlib import Path
from typing import List, Optional

from data.alert_loader import Alert
from utils.logger import get_logger

logger = get_logger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REPORT_DIR = PROJECT_ROOT / "reports"

# Color palette for PDF cells (must be reportlab-compatible hex strings).
TIER_COLORS = {
    "Critical": "#E53935",
    "High":     "#FB8C00",
    "Medium":   "#FDD835",
    "Low":      "#43A047",
}


def _ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def _timestamp_slug() -> str:
    return dt.datetime.now().strftime("%Y%m%d_%H%M%S")


# ---------------------------------------------------------------------- #
# PDF generation (reportlab)
# ---------------------------------------------------------------------- #
def generate_pdf(alerts: List[Alert],
                 output_path: Optional[Path] = None,
                 title: str = "SOC Triage Report") -> Path:
    """Generate a PDF triage report for the supplied alerts.

    Returns the path of the written PDF file.
    """
    # Lazy import so the rest of the tool still works without reportlab.
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
        )
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "reportlab is required for PDF generation. Run `pip install reportlab`."
        ) from exc

    if output_path is None:
        _ensure_dir(DEFAULT_REPORT_DIR)
        output_path = DEFAULT_REPORT_DIR / f"triage_report_{_timestamp_slug()}.pdf"
    else:
        _ensure_dir(Path(output_path).parent)
        output_path = Path(output_path)

    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=landscape(A4),
        title=title,
        author="SOC Triage Tool",
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "TitleStyle", parent=styles["Title"], fontSize=20, spaceAfter=6,
        textColor=colors.HexColor("#0F4C81"),
    )
    meta_style = ParagraphStyle(
        "Meta", parent=styles["Normal"], fontSize=9, textColor=colors.grey,
    )
    h2_style = ParagraphStyle(
        "H2", parent=styles["Heading2"], fontSize=13, spaceBefore=12,
        textColor=colors.HexColor("#0F4C81"),
    )
    body_style = ParagraphStyle(
        "Body", parent=styles["Normal"], fontSize=10, leading=13,
    )
    cell_style = ParagraphStyle(
        "Cell", parent=styles["Normal"], fontSize=8, leading=10,
    )

    story = []
    story.append(Paragraph(html.escape(title), title_style))
    story.append(Paragraph(
        f"Generated: {dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} "
        f"&nbsp;|&nbsp; Alerts: {len(alerts)} "
        f"&nbsp;|&nbsp; Tool: SOC Triage Tool",
        meta_style,
    ))
    story.append(Spacer(1, 8))

    # ----- Summary table -------------------------------------------------
    story.append(Paragraph("Alert Summary", h2_style))
    header = [
        Paragraph("<b>Time</b>", cell_style),
        Paragraph("<b>Alert</b>", cell_style),
        Paragraph("<b>Severity</b>", cell_style),
        Paragraph("<b>Src IP</b>", cell_style),
        Paragraph("<b>Country</b>", cell_style),
        Paragraph("<b>VT Mal.</b>", cell_style),
        Paragraph("<b>Abuse Conf.</b>", cell_style),
        Paragraph("<b>Risk</b>", cell_style),
        Paragraph("<b>Tier</b>", cell_style),
        Paragraph("<b>Status</b>", cell_style),
    ]
    data = [header]
    tier_row_colors: List[Optional[colors.Color]] = []
    for a in alerts:
        data.append([
            Paragraph(html.escape(a.timestamp or "-"), cell_style),
            Paragraph(html.escape(a.alert_name or "-"), cell_style),
            Paragraph(html.escape(a.severity or "-"), cell_style),
            Paragraph(html.escape(a.source_ip or "-"), cell_style),
            Paragraph(html.escape(a.country or "-"), cell_style),
            Paragraph(str(a.vt_malicious) if a.vt_malicious is not None else "-", cell_style),
            Paragraph(str(a.abuseipdb_confidence) if a.abuseipdb_confidence is not None else "-", cell_style),
            Paragraph(str(a.risk_score), cell_style),
            Paragraph(html.escape(a.risk_tier), cell_style),
            Paragraph(html.escape(a.status), cell_style),
        ])
        tier_row_colors.append(colors.HexColor(TIER_COLORS.get(a.risk_tier, "#FFFFFF")))

    col_widths = [22*mm, 50*mm, 20*mm, 28*mm, 25*mm, 15*mm, 20*mm, 14*mm, 18*mm, 25*mm]
    table = Table(data, colWidths=col_widths, repeatRows=1)
    ts = TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F4C81")),
        ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
    ])
    # Color the Tier cell per row.
    for i, c in enumerate(tier_row_colors, start=1):
        ts.add("BACKGROUND", (8, i), (8, i), c)
        ts.add("TEXTCOLOR",  (8, i), (8, i), colors.white if a.risk_tier in ("Critical", "High") else colors.black)
    table.setStyle(ts)
    story.append(table)
    story.append(Spacer(1, 10))

    # ----- Per-alert detail ---------------------------------------------
    story.append(PageBreak())
    story.append(Paragraph("Alert Details", h2_style))
    for idx, a in enumerate(alerts, start=1):
        story.append(Spacer(1, 6))
        story.append(Paragraph(
            f"<b>#{idx} {html.escape(a.alert_name)}</b> "
            f"<font color='{TIER_COLORS.get(a.risk_tier, '#000000')}'>"
            f"[{html.escape(a.risk_tier)} — risk {a.risk_score}]</font>",
            body_style,
        ))
        story.append(Paragraph(
            f"Time: {html.escape(a.timestamp or '-')} &nbsp;|&nbsp; "
            f"Severity: {html.escape(a.severity or '-')} &nbsp;|&nbsp; "
            f"Status: {html.escape(a.status)}",
            body_style,
        ))
        story.append(Paragraph(
            f"Source IP: {html.escape(a.source_ip or '-')} "
            f"({html.escape(a.country or 'unknown')}, {html.escape(a.isp or 'unknown ISP')})",
            body_style,
        ))
        story.append(Paragraph(
            f"Destination IP: {html.escape(a.destination_ip or '-')}",
            body_style,
        ))
        story.append(Paragraph(
            f"VirusTotal: {a.vt_malicious if a.vt_malicious is not None else 'n/a'} malicious &nbsp;|&nbsp; "
            f"AbuseIPDB: {a.abuseipdb_confidence if a.abuseipdb_confidence is not None else 'n/a'}% confidence",
            body_style,
        ))
        if a.notes:
            story.append(Paragraph(
                f"<b>Analyst notes:</b> {html.escape(a.notes)}",
                body_style,
            ))
        if a.raw_log:
            log_style = ParagraphStyle(
                "Log", parent=body_style, fontSize=8, leading=10,
                backColor=colors.HexColor("#F4F4F4"),
                borderColor=colors.HexColor("#CCCCCC"),
                borderWidth=0.25, borderPadding=4,
            )
            # Truncate very long logs to avoid blowing up the PDF.
            log_text = a.raw_log if len(a.raw_log) < 1500 else a.raw_log[:1500] + " …(truncated)"
            story.append(Paragraph(
                f"<b>Raw log:</b><br/>{html.escape(log_text)}",
                log_style,
            ))

    doc.build(story)
    logger.info("PDF report written to %s", output_path)
    return output_path


# ---------------------------------------------------------------------- #
# HTML generation
# ---------------------------------------------------------------------- #
_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>
  body {{ font-family: -apple-system, 'Segoe UI', Roboto, sans-serif;
          background: #0F1419; color: #E6E6E6; margin: 0; padding: 24px; }}
  h1 {{ color: #4FC3F7; border-bottom: 1px solid #2A3441; padding-bottom: 8px; }}
  h2 {{ color: #4FC3F7; margin-top: 32px; }}
  .meta {{ color: #8AA0B6; font-size: 12px; margin-bottom: 16px; }}
  table {{ border-collapse: collapse; width: 100%; font-size: 12px;
           background: #1A2332; }}
  th, td {{ border: 1px solid #2A3441; padding: 6px 8px; text-align: left;
            vertical-align: top; }}
  th {{ background: #0F4C81; color: white; }}
  tr:nth-child(even) td {{ background: #141C28; }}
  .tier-Critical {{ background: #E53935 !important; color: #fff; font-weight: bold; }}
  .tier-High     {{ background: #FB8C00 !important; color: #fff; font-weight: bold; }}
  .tier-Medium   {{ background: #FDD835 !important; color: #000; font-weight: bold; }}
  .tier-Low      {{ background: #43A047 !important; color: #fff; font-weight: bold; }}
  .alert-card {{ background: #1A2332; border: 1px solid #2A3441;
                 border-radius: 6px; padding: 14px 16px; margin: 12px 0; }}
  .alert-card h3 {{ margin: 0 0 6px 0; color: #4FC3F7; }}
  .kv {{ color: #B0BEC5; font-size: 12px; }}
  pre {{ background: #0F1419; border: 1px solid #2A3441; padding: 8px;
         font-size: 11px; overflow-x: auto; color: #B0BEC5;
         white-space: pre-wrap; word-wrap: break-word; }}
  .notes {{ color: #FFD54F; font-style: italic; }}
</style>
</head>
<body>
  <h1>{title}</h1>
  <div class="meta">Generated: {generated} &nbsp;|&nbsp; Alerts: {count} &nbsp;|&nbsp;
    Source: SOC Triage Tool</div>

  <h2>Alert Summary</h2>
  <table>
    <thead><tr>
      <th>Time</th><th>Alert</th><th>Severity</th><th>Src IP</th>
      <th>Country</th><th>VT Mal.</th><th>Abuse Conf.</th>
      <th>Risk</th><th>Tier</th><th>Status</th>
    </tr></thead>
    <tbody>
{summary_rows}
    </tbody>
  </table>

  <h2>Alert Details</h2>
{detail_cards}

</body>
</html>
"""


def _esc(s: Optional[str]) -> str:
    return html.escape(s or "")


def generate_html(alerts: List[Alert],
                  output_path: Optional[Path] = None,
                  title: str = "SOC Triage Report") -> Path:
    """Generate an HTML triage report. Returns the file path."""
    if output_path is None:
        _ensure_dir(DEFAULT_REPORT_DIR)
        output_path = DEFAULT_REPORT_DIR / f"triage_report_{_timestamp_slug()}.html"
    else:
        _ensure_dir(Path(output_path).parent)
        output_path = Path(output_path)

    summary_rows = []
    for a in alerts:
        summary_rows.append(
            "<tr>"
            f"<td>{_esc(a.timestamp)}</td>"
            f"<td>{_esc(a.alert_name)}</td>"
            f"<td>{_esc(a.severity)}</td>"
            f"<td>{_esc(a.source_ip)}</td>"
            f"<td>{_esc(a.country)}</td>"
            f"<td>{a.vt_malicious if a.vt_malicious is not None else '-'}</td>"
            f"<td>{a.abuseipdb_confidence if a.abuseipdb_confidence is not None else '-'}</td>"
            f"<td>{a.risk_score}</td>"
            f"<td><span class='tier-{_esc(a.risk_tier)}'>{_esc(a.risk_tier)}</span></td>"
            f"<td>{_esc(a.status)}</td>"
            "</tr>"
        )

    detail_cards = []
    for i, a in enumerate(alerts, start=1):
        notes_html = (f'<p class="notes"><b>Analyst notes:</b> {_esc(a.notes)}</p>'
                      if a.notes else "")
        log_text = a.raw_log if a.raw_log and len(a.raw_log) < 4000 else (a.raw_log or "")[:4000] + " …(truncated)"
        log_html = (f'<p><b>Raw log:</b></p><pre>{_esc(log_text)}</pre>'
                    if a.raw_log else "")
        detail_cards.append(f"""
        <div class="alert-card">
          <h3>#{i} {_esc(a.alert_name)}
            <span class="tier-{_esc(a.risk_tier)}" style="padding:2px 8px;border-radius:3px;font-size:11px;">
              {_esc(a.risk_tier)} — risk {a.risk_score}
            </span>
          </h3>
          <p class="kv">
            <b>Time:</b> {_esc(a.timestamp)} &nbsp;|&nbsp;
            <b>Severity:</b> {_esc(a.severity)} &nbsp;|&nbsp;
            <b>Status:</b> {_esc(a.status)}
          </p>
          <p class="kv">
            <b>Source IP:</b> {_esc(a.source_ip)}
            ({_esc(a.country)}, {_esc(a.isp)})
            &nbsp;|&nbsp;
            <b>Destination IP:</b> {_esc(a.destination_ip)}
          </p>
          <p class="kv">
            <b>VirusTotal:</b> {a.vt_malicious if a.vt_malicious is not None else 'n/a'} malicious
            &nbsp;|&nbsp;
            <b>AbuseIPDB:</b> {a.abuseipdb_confidence if a.abuseipdb_confidence is not None else 'n/a'}% confidence
            &nbsp;|&nbsp;
            <b>Categories:</b> {_esc(a.abuseipdb_category)}
          </p>
          {notes_html}
          {log_html}
        </div>
        """)

    output_path.write_text(
        _HTML_TEMPLATE.format(
            title=html.escape(title),
            generated=dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            count=len(alerts),
            summary_rows="\n".join(summary_rows),
            detail_cards="\n".join(detail_cards),
        ),
        encoding="utf-8",
    )
    logger.info("HTML report written to %s", output_path)
    return output_path


# ---------------------------------------------------------------------- #
# Ticketing stub (future)
# ---------------------------------------------------------------------- #
def create_ticket_stub(alert: Alert,
                       system: str = "thehive") -> str:
    """Stub for future ticketing integration.

    Returns a fake ticket ID.  Replace with a real API call (e.g.
    TheHive's ``/api/v1/alert`` or ServiceNow's ``/api/now/table/incident``)
    when integrating.
    """
    logger.info("Ticket stub called for alert %s on %s.", alert.alert_id, system)
    fake_id = f"{system.upper()}-STUB-{dt.datetime.now().strftime('%Y%m%d%H%M%S')}"
    return fake_id


__all__ = ["generate_pdf", "generate_html", "create_ticket_stub"]
