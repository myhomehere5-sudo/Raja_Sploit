#!/usr/bin/env python3
"""
modules/reporting.py

Robust reporting helper for Rajasploit.
- Finds the session/results to report on (supports both Rajasploit/results/<module> and Rajasploit/results/runX/<module> layouts)
- Collects files from modules 1..5 (configurable names)
- Generates a colored HTML report (no external libraries required)
- Generates a PDF report (using ReportLab if available)
- Produces small inline SVG bar charts (no matplotlib)
- Adds: centered professional title, detailed top summary, per-module short summaries, colorful charts,
  final note, and saves reports under results/reports
"""

from __future__ import annotations
import os
import sys
import time
from pathlib import Path
from datetime import datetime
from collections import defaultdict, Counter
import html
import mimetypes

# Optional PDF dependencies (ReportLab). PDF generation will gracefully skip with informative error if missing.
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors as rl_colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle
    REPORTLAB_AVAILABLE = True
except Exception:
    REPORTLAB_AVAILABLE = False

# ----------------- CONFIG -----------------
# Base project folder (adjust if your repo layout differs)
PROJECT_ROOT = Path.cwd()  # expects to be run from project root; change if needed
RESULTS_BASE = PROJECT_ROOT / "results"  # where sessions live (e.g., results/run1 or results/<module>)
# Reports should be stored in: Rajasploit/results/reports (per your request)
REPORT_DIR = PROJECT_ROOT / "results" / "reports"

# Module names to collect (Modules 1..5 typically). Add/remove names as your tool uses.
MODULE_NAMES = [
    "recon",                # reconnaissance
    "forensics",            # forensics & IR
    "defensive_monitoring", # defensive & monitoring (some users call it defensive)
    "defensive",            # alternate name
    "honeypot",             # honeypot
    "scanning",             # optional scanning module
    "exploitation",         # optional exploitation module
    "other"                 # a catch-all
]

# How many sample file contents to embed for text files per module
SAMPLE_LINES_PER_MODULE = 3
SAMPLE_CHAR_LIMIT = 500

# Colors (used for charts / module accents). Will cycle.
SVG_COLOR_PALETTE = ["#007bff", "#ff7f0e", "#2ca02c", "#d62728", "#9467bd", "#8c564b", "#e377c2", "#17becf"]

# ----------------- UTILITIES -----------------
def find_session_root(base: Path) -> Path:
    """
    Determine which folder to treat as the 'session' to report on.
    - If base contains expected module folders directly -> use base
    - Else, if base contains run*/session folders, pick most recently modified session folder
    """
    if not base.exists():
        raise FileNotFoundError(f"Results base path not found: {base}")

    entries = [p for p in base.iterdir() if p.is_dir()]
    entry_names = {p.name.lower() for p in entries}
    if entry_names & set(MODULE_NAMES):
        # results layout: results/<module> directly
        return base

    # Otherwise treat subdirectories as session runs and pick the latest
    session_dirs = entries
    if not session_dirs:
        raise FileNotFoundError(f"No session directories found under: {base}")
    latest = max(session_dirs, key=lambda p: p.stat().st_mtime)
    return latest

def collect_files_for_module(session_root: Path, module_name: str) -> list[Path]:
    """
    Flexible collection:
    - matches directories where the name equals module_name or contains module_name
    - collects files recursively
    """
    module_candidates = []
    for d in session_root.iterdir():
        if not d.is_dir():
            continue
        dn = d.name.lower()
        if dn == module_name.lower() or module_name.lower() in dn:
            module_candidates.append(d)
    if not module_candidates:
        return []
    files = []
    for moddir in module_candidates:
        for f in sorted(moddir.rglob("*")):
            if f.is_file():
                files.append(f)
    return sorted(files, key=lambda p: p.stat().st_mtime)

def file_summary_info(f: Path) -> dict:
    """Return small summary info for a file (size, mtime, mime)."""
    try:
        s = f.stat()
        mtime = datetime.fromtimestamp(s.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        size = s.st_size
    except Exception:
        mtime = "N/A"
        size = 0
    mime, _ = mimetypes.guess_type(str(f))
    return {"path": str(f), "name": f.name, "size": size, "mtime": mtime, "mime": mime or "unknown"}

def read_text_sample(f: Path, charlimit=SAMPLE_CHAR_LIMIT) -> str:
    """Read a small text sample from a file; handle binary safely."""
    try:
        text = f.read_text(errors="ignore")
        text = text.strip()
        if len(text) > charlimit:
            text = text[:charlimit] + "\n\n... (truncated)"
        return text
    except Exception:
        return "<unreadable>"

def human_size(n: int) -> str:
    """Human friendly byte size."""
    try:
        n = float(n)
    except Exception:
        return "0B"
    for unit in ['B','KB','MB','GB','TB']:
        if n < 1024:
            return f"{n:.0f}{unit}"
        n /= 1024.0
    return f"{n:.1f}PB"

# ----------------- HTML / SVG helpers -----------------
def svg_bar_chart(labels: list[str], values: list[int], width=560, height=140, palette=None) -> str:
    """Return an inline SVG bar chart (simple, multi-colored)."""
    palette = palette or SVG_COLOR_PALETTE
    if not values or sum(values) == 0:
        return "<div style='font-style:italic;color:#777'>No data for chart</div>"
    maxv = max(values)
    gap = 8
    bar_w = (width - (len(values)+1)*gap) / len(values)
    height_inner = height - 36  # reserve for labels
    parts = [f"<svg width='{width}' height='{height}' viewBox='0 0 {width} {height}' xmlns='http://www.w3.org/2000/svg'>"]
    parts.append(f"<rect x='0' y='0' width='{width}' height='{height}' fill='transparent' />")
    x = gap
    for i, v in enumerate(values):
        color = palette[i % len(palette)]
        bar_h = int((v / maxv) * height_inner) if maxv else 0
        y = height_inner - bar_h + 8
        parts.append(f"<rect x='{x:.1f}' y='{y:.1f}' width='{bar_w:.1f}' height='{bar_h:.1f}' rx='4' fill='{color}' opacity='0.95' />")
        lbl = html.escape(labels[i])[:12]
        parts.append(f"<text x='{x + bar_w/2:.1f}' y='{height - 6}' font-size='11' text-anchor='middle' fill='#333'>{lbl}</text>")
        parts.append(f"<text x='{x + bar_w/2:.1f}' y='{y - 4:.1f}' font-size='11' text-anchor='middle' fill='#222'>{v}</text>")
        x += bar_w + gap
    parts.append("</svg>")
    return "\n".join(parts)

def safe_html_escape(s: str) -> str:
    return html.escape(str(s))

# ----------------- REPORT BUILDING -----------------
def build_report(session_root: Path, out_path: Path, client_name="General", creator="Rajasploit", title=None):
    """
    Build full report and write HTML to out_path.
    Returns the path wrote.
    Also prepares a 'report' dict which can be passed to PDF generator.
    """
    start = datetime.now()
    title = title or f"Rajasploit Security Assessment — {session_root.name}"
    report = {
        "meta": {
            "session": str(session_root),
            "generated_at": start.strftime("%Y-%m-%d %H:%M:%S"),
            "client": client_name,
            "creator": creator,
            "title": title,
        },
        "modules": {}
    }

    # collect files for each module name
    for module in MODULE_NAMES:
        files = collect_files_for_module(session_root, module)
        if not files:
            continue
        info = [file_summary_info(f) for f in files]
        ext_counts = Counter([Path(i["name"]).suffix.lower() or "<noext>" for i in info])
        mime_counts = Counter([i["mime"].split("/")[0] if i["mime"] and "/" in i["mime"] else i["mime"] for i in info])
        mtimes = [i["mtime"] for i in info if i["mtime"] != "N/A"]
        # short auto-generated summary (one/two sentences)
        short_summary = (f"{len(info)} files collected. Top file types: "
                         + ", ".join(f"{k}({v})" for k, v in ext_counts.most_common(3)))
        # sample small text snippets
        samples = []
        text_like = [Path(i["path"]) for i in info if i["mime"] in ("text/plain", "unknown") or str(i["name"]).lower().endswith((".log", ".txt", ".json", ".csv"))]
        for t in text_like[:SAMPLE_LINES_PER_MODULE]:
            samples.append({"fname": t.name, "sample": read_text_sample(t)})
        report["modules"][module] = {
            "count_files": len(info),
            "size_total": sum(i["size"] for i in info),
            "ext_counts": dict(ext_counts.most_common()),
            "mime_counts": dict(mime_counts.most_common()),
            "first_mtime": min(mtimes) if mtimes else "N/A",
            "last_mtime": max(mtimes) if mtimes else "N/A",
            "files": info,
            "samples": samples,
            "short_summary": short_summary
        }

    # Build a dynamic overall/detailed summary for top of report
    total_files = sum(m["count_files"] for m in report["modules"].values()) or 0
    total_size = sum(m["size_total"] for m in report["modules"].values()) or 0
    all_ext_counts = Counter()
    all_mime_counts = Counter()
    mtime_earliest = None
    mtime_latest = None
    for m in report["modules"].values():
        all_ext_counts.update(m["ext_counts"])
        all_mime_counts.update(m["mime_counts"])
        if m["first_mtime"] != "N/A":
            try:
                t = datetime.strptime(m["first_mtime"], "%Y-%m-%d %H:%M:%S")
                if not mtime_earliest or t < mtime_earliest:
                    mtime_earliest = t
            except Exception:
                pass
        if m["last_mtime"] != "N/A":
            try:
                t = datetime.strptime(m["last_mtime"], "%Y-%m-%d %H:%M:%S")
                if not mtime_latest or t > mtime_latest:
                    mtime_latest = t
            except Exception:
                pass

    overall_summary = (
        f"Collected {total_files} files across {len(report['modules'])} module folders "
        f"({human_size(total_size)} total). Top extensions: "
        + ", ".join(f"{k}({v})" for k, v in all_ext_counts.most_common(5))
    )
    if mtime_earliest and mtime_latest:
        overall_summary += f". Data time range: {mtime_earliest.strftime('%Y-%m-%d %H:%M:%S')} → {mtime_latest.strftime('%Y-%m-%d %H:%M:%S')}."

    # Build HTML
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    out_path_parent = Path(out_path).parent
    out_path_parent.mkdir(parents=True, exist_ok=True)

    html_lines = []
    html_lines.append("<!doctype html><html><head><meta charset='utf-8'>")
    html_lines.append(f"<title>{safe_html_escape(report['meta']['title'])}</title>")
    # CSS — centered professional title + colorful accents
    html_lines.append(f"""
    <style>
      :root {{
        --bg: #f4f6f8;
        --card: #ffffff;
        --muted: #666;
        --accent-1: {SVG_COLOR_PALETTE[0]};
        --accent-2: {SVG_COLOR_PALETTE[1]};
        --accent-3: {SVG_COLOR_PALETTE[2]};
        --accent-4: {SVG_COLOR_PALETTE[3]};
      }}
      body{{font-family:Arial,Helvetica,sans-serif;background:var(--bg);color:#222;margin:0;padding:28px}}
      .container{{max-width:1100px;margin:0 auto}}
      .title-card{{background:linear-gradient(90deg, rgba(0,51,102,0.95), rgba(0,102,51,0.95));color:white;padding:28px 24px;border-radius:10px;text-align:center;box-shadow:0 8px 30px rgba(0,0,0,0.08)}}
      .title-card h1{{margin:0;font-size:28px;letter-spacing:0.6px}}
      .meta{{margin-top:8px;color:#dfeee0;font-size:14px}}
      .summary-card{{background:var(--card);padding:16px;margin-top:18px;border-radius:8px;box-shadow:0 6px 18px rgba(20,20,20,0.04)}}
      .module{{background:var(--card);padding:14px;margin-top:18px;border-radius:8px;box-shadow:0 6px 18px rgba(20,20,20,0.04)}}
      h2{{margin:6px 0 10px 0}}
      .small{{font-size:13px;color:var(--muted)}}
      table{{width:100%;border-collapse:collapse;margin-top:8px}}
      th,td{{padding:8px;border-bottom:1px solid #eee;text-align:left;font-size:13px}}
      .stat{{display:inline-block;padding:6px 8px;border-radius:6px;background:#eafaf0;color:#007a3a;font-weight:600}}
      pre{{background:#0f1720;color:#e6fff0;padding:10px;border-radius:6px;overflow:auto;max-height:220px}}
      .final-note{{background:#fff7e6;border-left:6px solid #ff9900;padding:12px;margin-top:18px;border-radius:6px}}
      .charts-row{{display:flex;gap:12px;flex-wrap:wrap}}
      .chart-box{{flex:1;min-width:260px;background:#fff;padding:10px;border-radius:8px;border:1px solid #f0f0f0}}
      .footer{{font-size:12px;color:#666;margin-top:18px;text-align:center}}
    </style>
    """)
    html_lines.append("</head><body>")
    html_lines.append("<div class='container'>")

    # Title
    html_lines.append("<div class='title-card'>")
    html_lines.append(f"<h1>{safe_html_escape(report['meta']['title'])}</h1>")
    html_lines.append(f"<div class='meta'>Client: {safe_html_escape(client_name)} &nbsp; | &nbsp; Creator: {safe_html_escape(creator)} &nbsp; | &nbsp; Generated: {report['meta']['generated_at']}</div>")
    html_lines.append("</div>")  # title-card

    # Overall summary (detailed)
    html_lines.append("<div class='summary-card'>")
    html_lines.append("<h2>Executive Summary</h2>")
    html_lines.append(f"<p class='small'>{safe_html_escape(overall_summary)}</p>")
    # quick stats
    html_lines.append(f"<p><span class='stat'>{total_files} files</span> across <strong>{len(report['modules'])}</strong> modules · Total size <strong>{human_size(total_size)}</strong></p>")
    html_lines.append("</div>")  # summary-card

    # Inline small charts area (top extensions and mime)
    # Top extensions chart data
    ext_items = list(all_ext_counts.items())[:8]
    if ext_items:
        labels = [k for k, _ in ext_items]
        values = [int(v) for _, v in ext_items]
        html_lines.append("<div class='charts-row'>")
        html_lines.append("<div class='chart-box'>")
        html_lines.append("<h3 style='margin-top:0'>Top File Extensions</h3>")
        html_lines.append(svg_bar_chart(labels, values, width=420, height=140))
        html_lines.append("</div>")
        # mime chart
        mime_items = list(all_mime_counts.items())[:8]
        labels2 = [k for k, _ in mime_items]
        values2 = [int(v) for _, v in mime_items]
        html_lines.append("<div class='chart-box'>")
        html_lines.append("<h3 style='margin-top:0'>Top MIME Types</h3>")
        html_lines.append(svg_bar_chart(labels2, values2, width=420, height=140))
        html_lines.append("</div>")
        html_lines.append("</div>")  # charts-row

    # Per-module details with short summary and charts
    for idx, (modname, data) in enumerate(report["modules"].items()):
        html_lines.append("<div class='module'>")
        accent = SVG_COLOR_PALETTE[idx % len(SVG_COLOR_PALETTE)]
        html_lines.append(f"<h2 style='color:{accent};margin-bottom:6px'>{safe_html_escape(modname)}</h2>")
        html_lines.append(f"<div class='small'>{safe_html_escape(data.get('short_summary','No summary'))}</div>")
        html_lines.append(f"<p class='small'>Files: <strong>{data['count_files']}</strong> · Size: <strong>{human_size(data['size_total'])}</strong> · Last modified: <strong>{data.get('last_mtime','N/A')}</strong></p>")

        # module-specific chart for top extensions
        ext_items = list(data["ext_counts"].items())[:6]
        if ext_items:
            labels = [k for k, _ in ext_items]
            values = [int(v) for _, v in ext_items]
            html_lines.append("<div style='margin:10px 0'>")
            html_lines.append(svg_bar_chart(labels, values, width=700, height=120, palette=SVG_COLOR_PALETTE))
            html_lines.append("</div>")

        # top files table
        html_lines.append("<details><summary>Top files (by modification time)</summary>")
        html_lines.append("<table><thead><tr><th>Name</th><th>Size</th><th>Mime</th><th>Modified</th></tr></thead><tbody>")
        for f in data["files"][-12:][::-1]:
            html_lines.append(f"<tr><td><code>{safe_html_escape(f['name'])}</code></td><td class='small'>{human_size(f['size'])}</td><td class='small'>{safe_html_escape(f['mime'])}</td><td class='small'>{safe_html_escape(f['mtime'])}</td></tr>")
        html_lines.append("</tbody></table></details>")

        # sample contents
        if data["samples"]:
            html_lines.append("<div style='margin-top:12px'><h4>Sample contents</h4>")
            for s in data["samples"]:
                html_lines.append(f"<div class='small'><strong>{safe_html_escape(s['fname'])}</strong></div>")
                html_lines.append(f"<pre>{safe_html_escape(s['sample'])}</pre>")
            html_lines.append("</div>")

        html_lines.append("</div>")  # module end

    # Final note & recommendations
    final_note = ("Critical findings should be reviewed and remediated immediately. Prioritize patching, access controls, "
                  "and monitoring for systems flagged by the defensive and honeypot modules. Schedule a follow-up scan after fixes.")
    html_lines.append(f"<div class='final-note'><h3>Final Note & Recommendations</h3><p class='small'>{safe_html_escape(final_note)}</p></div>")

    html_lines.append(f"<div class='footer'>Rajasploit report · Generated on {report['meta']['generated_at']}</div>")
    html_lines.append("</div>")  # container
    html_lines.append("</body></html>")

    out_path.write_text("\n".join(html_lines), encoding="utf-8")

    # attach additional metadata useful for PDF generation
    report["overall_summary"] = overall_summary
    report["total_files"] = total_files
    report["total_size"] = total_size
    return out_path, report

# ----------------- PDF generation -----------------
def generate_report_pdf(report: dict, pdf_path: Path):
    """
    Create a PDF that mirrors the HTML structure.
    If ReportLab is not available, raise an informative ImportError.
    """
    if not REPORTLAB_AVAILABLE:
        raise ImportError("ReportLab is not installed. Install with: pip install reportlab")

    doc = SimpleDocTemplate(str(pdf_path), pagesize=A4)
    elements = []
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "title",
        parent=styles["Title"],
        fontSize=20,
        alignment=1,
        textColor=rl_colors.HexColor("#003366"),
        spaceAfter=12,
    )
    section_title = ParagraphStyle(
        "section_title",
        parent=styles["Heading2"],
        textColor=rl_colors.HexColor("#006633"),
        spaceBefore=8,
        spaceAfter=6,
    )
    normal = styles["BodyText"]

    # Title block
    elements.append(Paragraph(report["meta"].get("title", "Rajasploit Security Assessment"), title_style))
    meta_line = f"Client: {report['meta'].get('client','N/A')}  |  Creator: {report['meta'].get('creator','N/A')}  |  Generated: {report['meta'].get('generated_at','N/A')}"
    elements.append(Paragraph(meta_line, normal))
    elements.append(Spacer(1, 12))

    # Executive summary
    elements.append(Paragraph("<b>Executive Summary</b>", section_title))
    elements.append(Paragraph(report.get("overall_summary", "No summary."), normal))
    elements.append(Spacer(1, 8))

    # Quick stats table
    stats_table = Table([["Total Files", report.get("total_files", 0)], ["Total Size", human_size(report.get("total_size", 0))]],
                        colWidths=[150, 300])
    stats_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), rl_colors.HexColor(SVG_COLOR_PALETTE[0])),
        ("TEXTCOLOR", (0, 0), (-1, 0), rl_colors.white),
        ("GRID", (0, 0), (-1, -1), 0.25, rl_colors.grey),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
    ]))
    elements.append(stats_table)
    elements.append(Spacer(1, 12))

    # Per-module sections
    colors_list = [rl_colors.HexColor(c) for c in SVG_COLOR_PALETTE]
    for i, (modname, data) in enumerate(report["modules"].items()):
        color = colors_list[i % len(colors_list)]
        elements.append(Paragraph(f"<font color='{color.hexval()}'><b>{modname}</b></font>", section_title))
        elements.append(Paragraph(data.get("short_summary", "No data."), normal))
        elements.append(Spacer(1, 6))
        # small table with core info
        t = Table([["Files Found", data.get("count_files", 0)], ["Total Size", human_size(data.get("size_total", 0))], ["Last Modified", data.get("last_mtime", "N/A")]],
                  colWidths=[140, 200])
        t.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.25, rl_colors.grey),
            ("BACKGROUND", (0, 0), (-1, 0), color),
            ("TEXTCOLOR", (0, 0), (-1, 0), rl_colors.white),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 6))
        # list top extensions (text)
        ext_summary = ", ".join(f"{k}({v})" for k, v in data.get("ext_counts", {}).items() if v)[:300]
        elements.append(Paragraph(f"<i>Top file types:</i> {ext_summary}", normal))
        elements.append(Spacer(1, 10))

    # Final recommendations
    elements.append(PageBreak())
    elements.append(Paragraph("<b>Final Note & Recommendations</b>", section_title))
    final_note = ("Critical findings should be reviewed and remediated immediately. Prioritize patch management, access control, "
                  "and continuous monitoring for flagged systems. Perform a re-scan after remediation.")
    elements.append(Paragraph(final_note, normal))
    elements.append(Spacer(1, 20))
    elements.append(Paragraph("<i>Report generated by Rajasploit</i>", normal))

    doc.build(elements)

# ----------------- CLI / Entrypoint -----------------
def interactive_mode():
    print("\n--- Rajasploit Reporting Module ---")
    print("This tool will look for results folders and generate HTML and/or PDF reports.")
    client = input("Client/Target name (leave blank for 'General'): ").strip() or "General"
    creator = input("Creator name/team (leave blank for 'Rajasploit'): ").strip() or "Rajasploit"

    try:
        session = find_session_root(RESULTS_BASE)
    except Exception as e:
        print(f"ERROR: {e}")
        return

    print(f"Using session root: {session}")
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_client = "".join(c for c in client if c.isalnum() or c in (' ', '_')).replace(' ', '_')
    html_filename = f"{safe_client}_Rajasploit_Report_{ts}.html"
    pdf_filename = f"{safe_client}_Rajasploit_Report_{ts}.pdf"
    html_out = REPORT_DIR / html_filename
    pdf_out = REPORT_DIR / pdf_filename

    print("Collecting files and building reports (this may take a few seconds)...")
    try:
        html_path, report = build_report(session, html_out, client_name=client, creator=creator)
    except Exception as e:
        print(f"ERROR building HTML report: {e}")
        return

    # Ask format selection
    print("\nSelect report format:")
    print("  1. HTML")
    print("  2. PDF")
    print("  3. Both HTML & PDF")
    choice = input("Enter choice (1/2/3) [default 3]: ").strip() or "3"

    if choice in ("1", "3"):
        print(f"[+] HTML report written to: {html_path.resolve()}")

    if choice in ("2", "3"):
        try:
            generate_report_pdf(report, pdf_out)
            print(f"[+] PDF report written to: {pdf_out.resolve()}")
        except ImportError as ie:
            print(f"[!] PDF generation failed: {ie}")
            print("[!] To enable PDF generation install ReportLab: pip install reportlab")
        except Exception as e:
            print(f"[!] PDF generation error: {e}")

    print("\nReport generation completed.")

# programmatic entry
def noninteractive_entry(session_path: str|None=None, client="General", creator="Rajasploit", out_html: str|None=None, out_pdf: str|None=None, generate_pdf=False):
    """
    Call from code:
      noninteractive_entry(session_path='results/run1', client='ACME', creator='TeamX', out_html='path/to/out.html', generate_pdf=True)
    """
    if session_path:
        session = Path(session_path)
        if not session.exists():
            raise FileNotFoundError(f"Provided session path does not exist: {session}")
    else:
        session = find_session_root(RESULTS_BASE)

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_client = "".join(c for c in client if c.isalnum() or c in (' ', '_')).replace(' ', '_')
    html_out = Path(out_html) if out_html else (REPORT_DIR / f"{safe_client}_Rajasploit_Report_{ts}.html")
    pdf_out = Path(out_pdf) if out_pdf else (REPORT_DIR / f"{safe_client}_Rajasploit_Report_{ts}.pdf")

    html_path, report = build_report(session, html_out, client_name=client, creator=creator)
    if generate_pdf:
        generate_report_pdf(report, pdf_out)
        return html_path, pdf_out
    return html_path

if __name__ == "__main__":
    interactive_mode()
