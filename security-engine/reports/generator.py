"""PDF security report (ReportLab)."""
import time
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

SEV_COLOR = {"LOW": "#3b82f6", "MEDIUM": "#d99a1e", "HIGH": "#e5622e", "CRITICAL": "#d9263a"}


def _t(ts) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts else "-"


def _table(rows, widths, sev_col=None):
    t = Table(rows, colWidths=widths, repeatRows=1)
    st = [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0e1729")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
          ("FONTSIZE", (0, 0), (-1, -1), 8), ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#b8c2d4")),
          ("VALIGN", (0, 0), (-1, -1), "TOP"), ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f3f6fb")])]
    if sev_col is not None:
        for i, r in enumerate(rows[1:], 1):
            c = SEV_COLOR.get(str(r[sev_col]).split()[0] if r[sev_col] else "")
            if c:
                st.append(("TEXTCOLOR", (sev_col, i), (sev_col, i), colors.HexColor(c)))
    t.setStyle(TableStyle(st))
    return t


def generate_report(db, out_dir: Path, hours: int = 24, include_demo: bool = False) -> Path:
    since = time.time() - hours * 3600
    demo = "" if include_demo else " AND is_demo=0"
    styles = getSampleStyleSheet()
    small = styles["BodyText"]
    small.fontSize = 8
    name = out_dir / f"security-report-{time.strftime('%Y%m%d-%H%M%S')}.pdf"
    doc = SimpleDocTemplate(str(name), pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=15 * mm, bottomMargin=15 * mm,
                            title="Endpoint Security Report")
    s = [Paragraph("Endpoint Security Center — Security Report", styles["Title"]),
         Paragraph(f"Generated {_t(time.time())} · period: last {hours} h · data processed and stored locally", small), Spacer(1, 6)]
    counts = {r["severity"]: r["n"] for r in db.query(f"SELECT severity, COUNT(*) n FROM alerts WHERE ts>=?{demo} GROUP BY severity", (since,))}
    total_events = db.one(f"SELECT COUNT(*) n FROM security_events WHERE ts>=?{demo}", (since,))["n"]
    s += [Paragraph("Summary", styles["Heading2"]),
          _table([["Total security events", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
                  [total_events] + [counts.get(k, 0) for k in ("LOW", "MEDIUM", "HIGH", "CRITICAL")]], [45 * mm] + [30 * mm] * 4)]
    cats = db.query(f"SELECT category, COUNT(*) n FROM alerts WHERE ts>=?{demo} GROUP BY category ORDER BY n DESC LIMIT 10", (since,))
    s += [Paragraph("Alerts by category", styles["Heading2"]),
          _table([["Category", "Count"]] + [[c["category"], c["n"]] for c in cats] or [["-", 0]], [120 * mm, 30 * mm])]
    inc = db.query(f"SELECT * FROM incidents WHERE updated_ts>=?{demo} ORDER BY risk_score DESC LIMIT 25", (since,))
    s += [Paragraph("Incidents", styles["Heading2"]),
          _table([["ID", "Severity", "Score", "Title", "Last update"]] +
                 [[i["id"], i["severity"], i["risk_score"], Paragraph(i["title"] or "", small), _t(i["updated_ts"])] for i in inc]
                 if inc else [["No incidents in this period"]], [38 * mm, 22 * mm, 15 * mm, 70 * mm, 35 * mm] if inc else [150 * mm], 1 if inc else None)]
    al = db.query(f"SELECT * FROM alerts WHERE ts>=?{demo} ORDER BY ts DESC LIMIT 60", (since,))
    s += [Paragraph("Recent alerts", styles["Heading2"]),
          _table([["Time", "Severity", "Category", "Source", "Description"]] +
                 [[_t(a["ts"]), a["severity"], Paragraph(a["category"] or "", small), a["source"] or "-", Paragraph(a["description"] or "", small)] for a in al]
                 if al else [["No alerts in this period"]], [32 * mm, 20 * mm, 32 * mm, 28 * mm, 68 * mm] if al else [150 * mm], 1 if al else None)]
    fe = db.query(f"SELECT * FROM file_events WHERE ts>=? AND risk!='LOW'{demo} ORDER BY ts DESC LIMIT 30", (since,))
    if fe:
        s += [Paragraph("File integrity events (medium and above)", styles["Heading2"]),
              _table([["Time", "Action", "Risk", "Path"]] + [[_t(f["ts"]), f["action"], f["risk"], Paragraph(f["path"], small)] for f in fe],
                     [32 * mm, 22 * mm, 20 * mm, 106 * mm], 2)]
    s += [Spacer(1, 10), Paragraph(
        "<b>Interpretation notes.</b> Risk levels (LOW 0–29, MEDIUM 30–59, HIGH 60–79, CRITICAL 80–100) are application-defined "
        "indicators derived from observable host and network behaviour. They are not attack probabilities. This tool cannot detect every "
        "possible cyberattack; a lack of alerts does not prove a system is uncompromised.", small)]
    doc.build(s)
    return name
