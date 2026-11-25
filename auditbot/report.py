"""Outputs: Rich terminal dashboard, audit evidence JSON, HTML executive brief."""
from __future__ import annotations

import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import __version__
from .scanner import ScanResult, sha256

console = Console(highlight=False, force_terminal=True if os.getenv("AUDITBOT_COLOR") == "1" else None)
SEV_STYLE = {"critical": "bold white on red", "high": "bold red", "medium": "yellow", "low": "dim"}
STATUS_STYLE = {"PASS": "bold green", "FAIL": "bold red", "N/A": "dim"}


def score_style(score: int) -> str:
    return "green" if score >= 85 else "yellow" if score >= 60 else "red"


def score_bar(score: int, width: int = 30) -> Text:
    filled = round(width * score / 100)
    t = Text("█" * filled, style=score_style(score))
    t.append("░" * (width - filled), style="dim")
    t.append(f"  {score}%", style=f"bold {score_style(score)}")
    return t


def coverage_warning(result: ScanResult) -> str | None:
    """A high score over 2 applicable tests means little: say so instead of implying the repo is safe."""
    applicable = sum(t["status"] != "N/A" for t in result.tests)
    if applicable < len(result.tests) // 2:
        return (f"Limited coverage: only {applicable} of {len(result.tests)} control tests apply to this codebase "
                f"(no cloud infrastructure-as-code found). Code checks are pattern-based (common injection, XSS and "
                f"TLS shortcuts); they don't replace a full application security test (SAST/DAST).")
    return None


def dashboard(result: ScanResult, target: str, ai: dict):
    evaluated = [t for t in result.tests if t["status"] != "N/A"]
    passed = sum(t["status"] == "PASS" for t in evaluated)
    head = Text()
    head.append("AUDIT READINESS  ", style="bold")
    head.append_text(score_bar(result.score))
    head.append("  (severity-weighted)", style="dim")
    head.append(f"\n{passed}/{len(evaluated)} control tests passing · {len(result.findings)} findings · "
                f"{len(result.files)} files scanned · target: {target}", style="dim")
    if coverage_warning(result):
        head.append(f"\n⚠ {coverage_warning(result)}", style="bold yellow")
    console.print(Panel(head, title="[bold]Audit Readiness Bot[/] · SOC 2 + ISO 27001:2022", border_style=score_style(result.score)))

    table = Table(show_lines=False, header_style="bold", expand=True)
    table.add_column("Status", width=6)
    table.add_column("Control test")
    table.add_column("SOC 2", style="cyan")
    table.add_column("ISO 27001", style="magenta")
    table.add_column("Sev")
    table.add_column("#", justify="right")
    order = {"FAIL": 0, "PASS": 1, "N/A": 2}
    for t in sorted(result.tests, key=lambda t: order[t["status"]]):
        table.add_row(Text(t["status"], style=STATUS_STYLE[t["status"]]), t["title"], ", ".join(t["soc2"]),
                      ", ".join(t["iso27001"]), Text(t["severity"], style=SEV_STYLE[t["severity"]]),
                      str(t["count"]) if t["count"] else "")
    console.print(table)

    if result.findings:
        notes = {f["id"]: f for f in ai.get("findings", [])}
        console.print("\n[bold]Findings[/]")
        for f in result.findings:
            loc = f"{f.file}:{f.line}" if f.file else "project-wide"
            console.print(Text.assemble((f" {f.severity.upper()} ", SEV_STYLE[f.severity]), "  ",
                                        (f"{f.id} ", "bold"), (loc, "underline"), "  ", (" ".join(f.soc2), "cyan")))
            console.print(f"   [dim]{f.snippet}[/]")
            if f.id in notes:
                console.print(f"   [bold]Risk:[/] {notes[f.id]['risk_explanation']}")
                console.print(f"   [bold green]Fix:[/] {notes[f.id]['remediation']}")
    if ai.get("executive_summary"):
        console.print(Panel(ai["executive_summary"], title=f"Executive summary · {ai.get('_source', '')}", border_style="blue"))


def _git_meta(root: Path) -> dict:
    def g(*a):
        try:
            return subprocess.run(["git", "-C", str(root), *a], capture_output=True, text=True, check=True).stdout.strip()
        except Exception:
            return None
    return {"git_commit": g("rev-parse", "HEAD"), "git_branch": g("rev-parse", "--abbrev-ref", "HEAD")}


def evidence(result: ScanResult, root: Path, ai: dict, label: str | None = None) -> dict:
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    notes = {f["id"]: f for f in ai.get("findings", [])}
    evaluated = [t for t in result.tests if t["status"] != "N/A"]
    return {
        "schema": "auditbot.evidence/v1",
        "generated_at": now,
        "tool": {"name": "audit-readiness-bot", "version": __version__},
        "target": {"path": label or str(root.resolve()), "name": label or root.resolve().name, **_git_meta(root)},
        "frameworks": ["AICPA SOC 2 TSC (2017, rev. 2022)", "ISO/IEC 27001:2022 Annex A"],
        "summary": {
            "readiness_score": result.score,
            "score_method": "severity-weighted share of passing control tests (critical 10, high 5, medium 2, low 1)",
            "coverage_warning": coverage_warning(result),
            "tests_evaluated": len(evaluated),
            "tests_passed": sum(t["status"] == "PASS" for t in evaluated),
            "tests_failed": sum(t["status"] == "FAIL" for t in evaluated),
            "findings": len(result.findings),
        },
        "control_tests": [{**t, "findings": [f.id for f in result.findings if f.rule == t["id"]]} for t in result.tests],
        "findings": [
            {**f.to_dict(),
             "file_sha256": sha256(result.files[f.file]) if f.file else None,
             "detected_at": now,
             **{k: notes.get(f.id, {}).get(k) for k in ("risk_explanation", "remediation", "auditor_note")}}
            for f in result.findings
        ],
        "executive_summary": ai.get("executive_summary"),
        "top_risks": ai.get("top_risks", []),
        "narrative_source": ai.get("_source"),
        "files_scanned": [{"path": p, "sha256": sha256(t)} for p, t in sorted(result.files.items())],
    }


def write_outputs(ev: dict, out_dir: Path) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    jp = out_dir / "evidence.json"
    jp.write_text(json.dumps(ev, indent=2, ensure_ascii=False), encoding="utf-8")
    env = Environment(loader=FileSystemLoader(Path(__file__).parent / "templates"), autoescape=select_autoescape())
    hp = out_dir / "report.html"
    hp.write_text(env.get_template("report.html").render(ev=ev), encoding="utf-8")
    # Static single-page brief without the interactive tabs (also the safe fallback for print/email).
    (out_dir / "report-classic.html").write_text(env.get_template("report_classic.html").render(ev=ev), encoding="utf-8")
    return jp, hp
