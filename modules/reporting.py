#!/usr/bin/env python3
"""
modules/reporting.py

Professional Rajasploit Reporting Module (auto-detect session results, summarize, generate PDF + HTML).

- Auto-detects latest session folder under common result dirs.
- Summarizes activity for Modules 1..6 (counts of text/log/json/csv and images).
- Embeds charts and images and writes a polished PDF (ReportLab).
- Also writes an HTML copy for quick review.

Dependencies:
  pip3 install reportlab matplotlib
(HTML output uses plain files; no extra deps)

Drop into modules/ and call from main menu.
"""
import os
import sys
import io
import glob
import math
import json
import shutil
import textwrap
from datetime import datetime
from collections import defaultdict, Counter

# PDF + layout
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Image,
    Table,
    TableStyle,
    PageBreak,
    KeepTogether,
)

# plotting for a small summary chart
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# ------------- Configuration -------------
MODULE_LABELS = {
    1: "Reconnaissance",
    2: "Attacks & Exploitation",
    3: "Forensics & Incident Response",
    4: "Defensive & Monitoring",
    5: "Honeypot",
    6: "Extra Features"
}

# file type buckets and their readable names
EXT_BUCKETS = {
    'text': ('.txt', '.log', '.md'),
    'json': ('.json',),
    'csv' : ('.csv',),
    'image': ('.png', '.jpg', '.jpeg', '.svg'),
    'pdf' : ('.pdf',),
}

TRUNCATE_TEXT_CHARS = 2500  # inline text show limit

# ---------------- Helpers ----------------
def find_candidate_session_dirs(base_paths=None):
    """Return list of candidate session directories (absolute paths)."""
    if base_paths is None:
        base_paths = ['results', 'session_results', 'reports', os.getcwd()]
    candidates = []
    for base in base_paths:
        if not os.path.isabs(base):
            base = os.path.join(os.getcwd(), base)
        if not os.path.exists(base):
            continue
        # if base is a session dir itself add; otherwise add its subdirs
        if any(pat in os.path.basename(base).lower() for pat in ('session', 'run', 'results', 'report')):
            candidates.append(os.path.abspath(base))
        # include subdirectories
        for entry in os.listdir(base):
            path = os.path.join(base, entry)
            if os.path.isdir(path):
                candidates.append(os.path.abspath(path))
    # deduplicate and sort by mtime desc
    uniq = list(dict.fromkeys(candidates))
    uniq.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    return uniq

def auto_detect_session_folder():
    cand = find_candidate_session_dirs()
    if cand:
        return cand[0]
    # fallback: check modules subfolders per-module
    fallback = os.path.join(os.getcwd(), 'session_results')
    return fallback if os.path.exists(fallback) else os.getcwd()

def module_folder_candidates(session_dir, module_index):
    """
    Returns list of candidate folders for a module.
    Preferred: session_dir/module_{i} (or module-i), else folders containing a module name hint.
    """
    candidates = []
    names = [f"module_{module_index}", f"module-{module_index}", f"module{module_index}"]
    # also add common synonyms
    synonyms = {
        1: ['recon','reconnaissance'],
        2: ['attack','attacks','exploitation','exploit'],
        3: ['forensic','forensics','incident'],
        4: ['defensive','monitor','monitoring'],
        5: ['honeypot','honey'],
        6: ['extra','extras','utilities','tools']
    }.get(module_index, [])

    for name in names + synonyms:
        p = os.path.join(session_dir, name)
        if os.path.isdir(p):
            candidates.append(p)

    # scan top-level session dir for folders containing synonyms
    for entry in os.listdir(session_dir):
        p = os.path.join(session_dir, entry)
        if not os.path.isdir(p):
            continue
        low = entry.lower()
        for syn in synonyms + names:
            if syn in low and p not in candidates:
                candidates.append(p)
    return candidates

def classify_files(file_paths):
    """Return counts per ext bucket and list of categorized files."""
    counts = Counter()
    categorized = defaultdict(list)
    for fp in file_paths:
        lower = fp.lower()
        ext = os.path.splitext(lower)[1]
        matched = False
        for cat, exts in EXT_BUCKETS.items():
            if ext in exts:
                categorized[cat].append(fp)
                counts[cat] += 1
                matched = True
                break
        if not matched:
            categorized['other'].append(fp)
            counts['other'] += 1
    return counts, categorized

def collect_module_results(session_dir, module_index):
    """Return summary dict for a module: folder used, file list, counts & categorized files."""
    folder_candidates = module_folder_candidates(session_dir, module_index)
    # pick the first candidate if exists else search for files that match module name
    chosen = None
    if folder_candidates:
        chosen = folder_candidates[0]
        files = []
        for root, _, filenames in os.walk(chosen):
            for fn in filenames:
                files.append(os.path.join(root, fn))
    else:
        # fallback: search for files in session_dir matching module keywords
        keywords = [MODULE_LABELS[module_index].split()[0].lower()]  # e.g. 'Reconnaissance' -> 'reconnaissance'
        files = []
        for root, _, filenames in os.walk(session_dir):
            for fn in filenames:
                low = fn.lower()
                if any(k in low for k in keywords) or f"module{module_index}" in low:
                    files.append(os.path.join(root, fn))
        if files:
            chosen = os.path.commonpath([os.path.abspath(f) for f in files])
    counts, categorized = classify_files(files)
    total_files = sum(counts.values())
    return {
        'module_index': module_index,
        'module_name': MODULE_LABELS.get(module_index, f"Module {module_index}"),
        'folder': chosen,
        'files': files,
        'counts': dict(counts),
        'categorized': dict(categorized),
        'total_files': total_files
    }

# ---------- Visual helpers ----------
def make_summary_chart(mod_summaries, out_path):
    """Create a small bar chart: visuals vs logs per module."""
    modules = []
    visuals = []
    texts = []
    for s in mod_summaries:
        modules.append(s['module_name'])
        cat = s['counts']
        visuals.append(cat.get('image', 0))
        texts.append(cat.get('text', 0) + cat.get('json', 0) + cat.get('csv', 0) + cat.get('pdf', 0) + cat.get('other', 0))
    x = range(len(modules))
    width = 0.35
    plt.figure(figsize=(8,2.4))
    plt.bar([i - width/2 for i in x], visuals, width=width, label='Visuals (png/jpg)')
    plt.bar([i + width/2 for i in x], texts, width=width, label='Text / Data')
    plt.xticks(x, modules, rotation=25, fontsize=8)
    plt.legend(fontsize=8)
    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close()

def scaled_image(path, max_width_cm=16, max_height_cm=10):
    """Return width, height in points suitable for ReportLab Image call (scale to fit)."""
    try:
        from PIL import Image as PILImage
    except Exception:
        # fallback: return default
        return (max_width_cm*cm, max_height_cm*cm)
    try:
        im = PILImage.open(path)
        w, h = im.size
        dpi = im.info.get('dpi', (96,96))[0] if isinstance(im.info.get('dpi', None), tuple) else 96
        # convert pixels to points: 1 pt = 1/72 inch. points = pixels * 72 / dpi
        pw = w * 72.0 / dpi
        ph = h * 72.0 / dpi
        maxpw = max_width_cm * cm
        maxph = max_height_cm * cm
        scale = min(1.0, maxpw / pw if pw else 1.0, maxph / ph if ph else 1.0)
        return (pw*scale, ph*scale)
    except Exception:
        return (max_width_cm*cm, max_height_cm*cm)

# ---------- Build report ----------
def generate_polished_report(session_dir=None):
    # detect session
    detected = auto_detect_session_folder()
    if session_dir is None:
        session_dir = input(f"Session folder (press Enter to use detected: {detected}): ").strip() or detected
    session_dir = os.path.abspath(session_dir)
    if not os.path.exists(session_dir) or not os.path.isdir(session_dir):
        print(f"[!] Session folder does not exist: {session_dir}")
        return

    # metadata
    client = input("Client name: ").strip() or "UnknownClient"
    creator = input("Creator name: ").strip() or os.getlogin() if hasattr(os, 'getlogin') else "UnknownCreator"
    title = input("Report title: ").strip() or f"Rajasploit Report {datetime.now().strftime('%Y%m%d_%H%M%S')}"

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    timestamp_file = datetime.now().strftime("%Y%m%d_%H%M%S")
    pdf_name = os.path.join(session_dir, f"Rajasploit_Report_{timestamp_file}.pdf")
    html_name = os.path.join(session_dir, f"Rajasploit_Report_{timestamp_file}.html")

    # gather module summaries
    module_summaries = []
    for i in range(1,7):
        module_summaries.append(collect_module_results(session_dir, i))

    # overall metrics
    overall = Counter()
    for s in module_summaries:
        overall.update(s['counts'])

    # prepare chart
    chart_path = os.path.join(session_dir, f"_report_summary_chart_{timestamp_file}.png")
    try:
        make_summary_chart(module_summaries, chart_path)
        chart_exists = True
    except Exception:
        chart_exists = False

    # ---------------- ReportLab document build ----------------
    doc = SimpleDocTemplate(pdf_name, pagesize=A4,
                            rightMargin=1.6*cm, leftMargin=1.6*cm,
                            topMargin=1.6*cm, bottomMargin=1.6*cm)
    styles = getSampleStyleSheet()
    # custom styles
    title_style = ParagraphStyle('Title', parent=styles['Title'], fontSize=22, textColor=colors.HexColor('#0b4f8a'), alignment=1)
    heading_style = ParagraphStyle('Heading', parent=styles['Heading2'], fontSize=14, textColor=colors.HexColor('#0b6fbf'), spaceAfter=6)
    normal = ParagraphStyle('Normal', parent=styles['Normal'], fontSize=10, leading=13)
    small = ParagraphStyle('Small', parent=styles['Normal'], fontSize=9, leading=11, textColor=colors.HexColor('#444444'))

    story = []

    # cover
    story.append(Paragraph(title, title_style))
    story.append(Spacer(1, 6))
    info = [
        ["Client:", client],
        ["Creator:", creator],
        ["Session folder:", session_dir],
        ["Generated:", timestamp]
    ]
    info_table = Table(info, colWidths=(3.5*cm, 11*cm))
    info_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.whitesmoke),
        ('BOX', (0,0), (-1,-1), 0.75, colors.grey),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
        ('FONTSIZE', (0,0), (-1,-1), 10),
    ]))
    story.append(info_table)
    story.append(Spacer(1,12))

    # Executive summary + analytics table
    story.append(Paragraph("Executive Summary", heading_style))
    exec_text = (
        f"This report captures results collected in the session folder <b>{os.path.basename(session_dir)}</b>. "
        "The following analysis summarizes the modules executed, key files captured, and visualizations produced. "
        "Use the module sections to review raw outputs and charts for technical details and evidence."
    )
    story.append(Paragraph(exec_text, normal))
    story.append(Spacer(1,10))

    # analytics table
    table_data = [["Module", "Files", "Visuals", "Logs/Text", "JSON/CSV", "Other"]]
    for s in module_summaries:
        counts = s['counts']
        row = [
            s['module_name'],
            str(s['total_files']),
            str(counts.get('image',0)),
            str(counts.get('text',0)+counts.get('log',0) if 'log' in counts else counts.get('text',0)),
            str(counts.get('json',0)+counts.get('csv',0)),
            str(counts.get('other',0))
        ]
        table_data.append(row)
    analytics = Table(table_data, colWidths=[6*cm, 2*cm, 2*cm, 2*cm, 2*cm, 2*cm])
    analytics.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#eaf3ff')),
        ('GRID', (0,0), (-1,-1), 0.4, colors.grey),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 9),
    ]))
    story.append(analytics)
    story.append(Spacer(1,10))

    if chart_exists:
        story.append(Paragraph("Visual Summary (Visuals vs Text/Data)", small))
        try:
            w,h = scaled_image(chart_path, max_width_cm=16, max_height_cm=4)
            story.append(Image(chart_path, width=w, height=h))
            story.append(Spacer(1,12))
        except Exception:
            pass

    story.append(PageBreak())

    # Per-module detailed sections
    for s in module_summaries:
        story.append(Paragraph(f"<u>{s['module_name']}</u>", heading_style))
        story.append(Spacer(1,6))
        # short summary box
        summ_lines = [
            f"Folder: {s['folder'] if s['folder'] else 'Auto-detected or mixed (see files below)'}",
            f"Total files: {s['total_files']}",
            "Counts: " + ", ".join(f"{k}={v}" for k,v in s['counts'].items())
        ]
        summ_para = Paragraph("<br/>".join(summ_lines), small)
        summ_table = Table([[summ_para]], colWidths=[15*cm])
        summ_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#fafafa')),
            ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#d0d0d0')),
            ('LEFTPADDING', (0,0), (-1,-1), 6),
            ('RIGHTPADDING', (0,0), (-1,-1), 6),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ]))
        story.append(summ_table)
        story.append(Spacer(1,8))

        # Include images first (if any)
        images = s['categorized'].get('image', []) or []
        for img in images:
            try:
                w,h = scaled_image(img, max_width_cm=16, max_height_cm=10)
                story.append(Image(img, width=w, height=h))
                story.append(Spacer(1,8))
            except Exception:
                story.append(Paragraph(f"[Image could not be embedded: {os.path.basename(img)}]", small))

        # Include small textual files (truncate if too big)
        text_files = (s['categorized'].get('text', []) +
                      s['categorized'].get('json', []) +
                      s['categorized'].get('csv', []) +
                      s['categorized'].get('pdf', []))  # pdf listed as file but we won't embed page contents
        for tf in text_files:
            try:
                ext = os.path.splitext(tf)[1].lower()
                # read safely
                content = ""
                if ext == '.pdf':
                    # list PDF filename only
                    content = f"[PDF file captured: {os.path.basename(tf)}]"
                else:
                    with open(tf, 'r', errors='ignore') as fh:
                        content = fh.read(TRUNCATE_TEXT_CHARS+200)
                    if len(content) > TRUNCATE_TEXT_CHARS:
                        content = content[:TRUNCATE_TEXT_CHARS] + "\n\n... (truncated) ..."
                # display inside a box
                txt = Paragraph(f"<b>{os.path.basename(tf)}</b><br/><pre>{content}</pre>", small)
                box = Table([[txt]], colWidths=[15*cm])
                box.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,-1), colors.white),
                    ('BOX', (0,0), (-1,-1), 0.4, colors.HexColor('#cccccc')),
                    ('LEFTPADDING', (0,0), (-1,-1), 6),
                    ('RIGHTPADDING', (0,0), (-1,-1), 6),
                    ('TOPPADDING', (0,0), (-1,-1), 6),
                ]))
                story.append(box)
                story.append(Spacer(1,8))
            except Exception as e:
                story.append(Paragraph(f"[Error reading {os.path.basename(tf)}: {e}]", small))

        story.append(PageBreak())

    # footer page with notes & actions
    story.append(Paragraph("Notes & Recommendations", heading_style))
    notes = (
        "This report aggregates results recorded during the session. Files larger than a certain threshold are truncated for in-report display — "
        "use the archived session folder to access complete logs and artifacts. Recommendations:\n"
        "- Validate any suspicious IPs found in Recon.\n- Review the AutoVuln Nmap & Nikto logs for actionable vulnerabilities.\n"
        "- Preserve disk images and memory extracts securely for forensic analysis."
    )
    story.append(Paragraph(notes, normal))
    story.append(Spacer(1,12))

    # build the document
    try:
        doc.build(story)
        print(f"\n[+] PDF report created: {pdf_name}")
    except Exception as e:
        print(f"[!] Failed to build PDF: {e}")

    # Minimal HTML export for convenience (mirrors the structure lightly)
    try:
        with open(html_name, 'w', encoding='utf-8') as hf:
            hf.write(f"<html><head><meta charset='utf-8'><title>{title}</title></head><body>")
            hf.write(f"<h1>{title}</h1><p><b>Client:</b> {client} &nbsp; <b>Creator:</b> {creator} &nbsp; <b>Date:</b> {timestamp}</p>")
            hf.write("<h2>Executive Summary</h2>")
            hf.write(f"<p>{exec_text}</p>")
            hf.write("<h2>Analytics</h2>")
            hf.write("<table border='1' cellpadding='4'><tr><th>Module</th><th>Files</th><th>Visuals</th><th>Logs/Text</th><th>JSON/CSV</th><th>Other</th></tr>")
            for s in module_summaries:
                c = s['counts']
                hf.write(f"<tr><td>{s['module_name']}</td><td>{s['total_files']}</td><td>{c.get('image',0)}</td><td>{c.get('text',0)}</td><td>{c.get('json',0)+c.get('csv',0)}</td><td>{c.get('other',0)}</td></tr>")
            hf.write("</table>")
            if chart_exists:
                hf.write(f"<h3>Visual Summary</h3><img src=\"{os.path.basename(chart_path)}\" style='max-width:800px'><br/>")
                # copy chart to session dir alongside HTML for proper display
                try:
                    shutil.copyfile(chart_path, os.path.join(session_dir, os.path.basename(chart_path)))
                except Exception:
                    pass
            for s in module_summaries:
                hf.write(f"<h2>{s['module_name']}</h2>")
                hf.write(f"<p>Folder: {s['folder']}</p>")
                if s['files']:
                    hf.write("<ul>")
                    for f in s['files']:
                        name = os.path.basename(f)
                        hf.write(f"<li>{name} ({os.path.splitext(name)[1]})</li>")
                    hf.write("</ul>")
                else:
                    hf.write("<p>No files captured.</p>")
            hf.write("</body></html>")
        print(f"[+] HTML report created: {html_name}")
    except Exception as e:
        print(f"[!] Failed to create HTML report: {e}")

# ---------- CLI entry ----------
def main():
    print("Rajasploit — Professional Reporting Module")
    print("This module will scan your session results and create a polished PDF report.")
    generate_polished_report()

if __name__ == "__main__":
    main()
