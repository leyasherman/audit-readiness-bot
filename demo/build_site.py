"""Build the GitHub Pages demo in docs/ from a clean scan of demo-target.
Run:  python demo/setup_demo.py && python demo/build_site.py"""
import subprocess
import sys
from pathlib import Path

project = Path(__file__).resolve().parent.parent
docs = project / "docs"
REPO = "https://github.com/leyasherman/audit-readiness-bot"
ABOUT = ("Audit Readiness Bot scans infrastructure code, maps findings to SOC 2 and ISO 27001, "
         "and blocks commits that break compliance. Interactive demo report.")

HEAD = f"""<meta name="description" content="{ABOUT}">
<meta property="og:title" content="Audit Readiness Bot: live demo">
<meta property="og:description" content="{ABOUT}">
<meta property="og:type" content="website">
<meta property="og:image" content="https://leyasherman.github.io/audit-readiness-bot/img/report.png">
</head>"""

BANNER = f"""<div style="position:relative;z-index:21;text-align:center;font:500 13px/1.5 var(--sans);color:var(--muted);margin:0 auto 18px">
    Live demo on <b style="color:var(--ink)">Acme Health</b>, a fictional company with planted compliance gaps ·
    <a href="{REPO}" style="color:var(--cyan)">How it works and source code on GitHub</a></div>
  <nav class="tabs\""""


def replace_once(html: str, old: str, new: str) -> str:
    if html.count(old) != 1:
        sys.exit(f"build_site: expected exactly one {old!r} in the report, found {html.count(old)}")
    return html.replace(old, new)


subprocess.run([sys.executable, "-m", "auditbot", "scan", "demo-target", "--no-ai", "--out", "docs"], cwd=project, check=True)

html = (docs / "report.html").read_text(encoding="utf-8")
html = replace_once(html, "</head>", HEAD)
html = replace_once(html, '<nav class="tabs"', BANNER)
html = replace_once(html, "machine-readable evidence: evidence.json",
                    'machine-readable evidence: <a href="evidence.json" style="color:var(--cyan)">evidence.json</a> · '
                    '<a href="report-classic.html" style="color:var(--cyan)">single-page report</a>')
(docs / "index.html").write_text(html, encoding="utf-8", newline="\n")
(docs / "report.html").unlink()
(docs / ".nojekyll").touch()
print("Built docs/index.html")
