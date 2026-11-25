"""audit-bot CLI.

  python -m auditbot scan <repo>                 full assessment -> dashboard + evidence.json + report.html
  python -m auditbot check <repo> [--staged]     change gate: only NEW violations vs HEAD (or --base REF)
  python -m auditbot fix <repo> [--dry-run]      apply fixes that a re-scan proves correct
  python -m auditbot install-hook <repo>         block commits that introduce violations
  add --online to scan/check/fix to verify dependencies against PyPI/npm (hallucinated or brand-new packages)
"""
from __future__ import annotations

import argparse
import difflib
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

from rich.panel import Panel
from rich.text import Text

from .enrich import enrich
from .fixer import plan_fixes
from .report import SEV_STYLE, console, dashboard, evidence, score_bar, write_outputs
from .scanner import files_from_dir, files_from_rev, scan


def _is_url(p: str) -> bool:
    return bool(re.match(r"^(https?://|git@)", p))


def _rmtree(p: Path):
    def force(fn, path, _exc):  # git marks pack files read-only on Windows
        os.chmod(path, stat.S_IWRITE)
        fn(path)
    shutil.rmtree(p, onerror=force)


def cmd_scan(a):
    if not _is_url(a.path):
        return _scan(a, Path(a.path))
    tmp = Path(tempfile.mkdtemp(prefix="auditbot-"))
    try:
        with console.status(f"Cloning {a.path} ..."):
            r = subprocess.run(["git", "clone", "-q", "--depth", "1", a.path, str(tmp / "repo")],
                               capture_output=True, text=True)
        if r.returncode:
            console.print(f"[red]Could not clone {a.path}:[/] {r.stderr.strip()}")
            return 2
        return _scan(a, tmp / "repo")
    finally:
        _rmtree(tmp)


def _scan(a, root: Path):
    label = a.path
    with console.status("Scanning configuration and mapping to controls..."):
        result = scan(files_from_dir(root))
    with console.status("Claude is writing risk analysis and executive brief..."):
        ai = enrich([f.to_dict() for f in result.findings], result.score, "full audit readiness scan", use_ai=not a.no_ai)
    dashboard(result, label, ai)
    jp, hp = write_outputs(evidence(result, root, ai, label=label), Path(a.out))
    console.print(f"\n[bold]Evidence:[/] {jp}\n[bold]Report:[/]   {hp}")
    return 0


def _write_preserving_newlines(path: Path, text: str):
    crlf = path.exists() and b"\r\n" in path.read_bytes()
    path.write_text(text, encoding="utf-8", newline="\r\n" if crlf else "\n")


def cmd_fix(a):
    root = Path(a.path)
    files = files_from_dir(root)
    before = scan(files)
    rules = set(a.rule) if a.rule else None
    with console.status("Writing fixes and re-scanning to verify each one..."):
        fixes, unfixed, final = plan_fixes(files, use_ai=not a.no_ai, rules=rules)
    after = scan(final)

    for fx in fixes:
        body = Text()
        loc = fx.path if fx.finding.file == fx.path else f"{fx.finding.file or 'project-wide'} → {fx.path}"
        body.append(loc + "\n", style="underline")
        body.append(fx.summary + "\n", style="")
        body.append(f"Verified: re-scan shows the violation gone and no new ones · source: {fx.source}", style="dim green")
        console.print(Panel(body, title=Text.assemble(("  FIXED  ", "bold white on green"), f"  {fx.finding.title}"),
                            title_align="left", border_style="green"))
    changed = [p for p in final if final[p] != files.get(p)]
    for p in changed:
        diff = difflib.unified_diff(files[p].splitlines(), final[p].splitlines(), f"a/{p}", f"b/{p}", lineterm="", n=1)
        for line in diff:
            style = "green" if line.startswith("+") else "red" if line.startswith("-") else "cyan" if line.startswith("@@") else "dim"
            console.print(Text(line, style=style))
    for f in unfixed:
        console.print(f"[yellow]NEEDS A HUMAN[/]  {f.title}  [dim]{f.file or 'project-wide'}"
                      f"{':' + str(f.line) if f.line else ''}[/]  [dim](no fix could be verified automatically)[/]")

    head = Text("AUTO-REMEDIATION  ", style="bold")
    head.append(f"{before.score}% → ", style="dim")
    head.append_text(score_bar(after.score, 20))
    head.append(f"  ({after.score - before.score:+d})", style="green")
    head.append(f"\n{len(fixes)} verified fix(es) in {len(changed)} file(s) · {len(unfixed)} need a human decision", style="dim")
    console.print(Panel(head, border_style="green" if fixes else "yellow", title="[bold]Audit Readiness Bot"))

    if a.dry_run:
        console.print("[dim]Dry run: no files were changed.[/]")
    else:
        for p in changed:
            _write_preserving_newlines(root / p, final[p])
        if changed:
            console.print(f"[green]✔ Applied to {len(changed)} file(s).[/] Review the diff, then commit.")
    return 0


def cmd_check(a):
    root = Path(a.path)
    try:
        base_files = files_from_rev(root, a.base)
    except subprocess.CalledProcessError:
        base_files = {}  # first commit: everything is new
    cur_files = files_from_rev(root, "") if a.staged else files_from_dir(root)
    base, cur = scan(base_files), scan(cur_files)

    base_keys = {f.key() for f in base.findings}
    cur_keys = {f.key() for f in cur.findings}
    new = [f for f in cur.findings if f.key() not in base_keys]
    fixed = [f for f in base.findings if f.key() not in cur_keys]

    delta = cur.score - base.score
    head = Text("COMPLIANCE GATE  ", style="bold")
    head.append(f"{base.score}% → ", style="dim")
    head.append_text(score_bar(cur.score, 20))
    head.append(f"  ({delta:+d})", style="green" if delta >= 0 else "bold red")
    head.append(f"\nChange vs {a.base if not a.staged else 'HEAD (staged changes)'}: "
                f"{len(new)} new violation(s), {len(fixed)} fixed", style="dim")
    console.print(Panel(head, border_style="red" if new else "green", title="[bold]Audit Readiness Bot"))

    if new:
        with console.status("Claude is reviewing the change..."):
            ai = enrich([f.to_dict() for f in new], cur.score, "pre-commit review of a code change", use_ai=not a.no_ai)
        notes = {n["id"]: n for n in ai.get("findings", [])}
        for f in new:
            body = Text()
            body.append(f"{f.file}:{f.line}\n" if f.file else "project-wide\n", style="underline")
            body.append(f"  {f.snippet}\n", style="dim")
            body.append("Breaks: ", style="bold")
            body.append(f"SOC 2 {', '.join(f.soc2)}", style="cyan")
            body.append(" · ")
            body.append(f"ISO 27001 {', '.join(f.iso27001)}\n", style="magenta")
            n = notes.get(f.id)
            if n:
                body.append("Risk: ", style="bold")
                body.append(n["risk_explanation"] + "\n")
                body.append("Fix:  ", style="bold green")
                body.append(n["remediation"])
            console.print(Panel(body, title=Text.assemble((f" {f.severity.upper()} ", SEV_STYLE[f.severity]), f"  {f.title}"),
                                title_align="left", border_style="red"))
        console.print(f"[dim]narrative: {ai.get('_source')}[/]")
    for f in fixed:
        console.print(f"[bold green]FIXED[/]  {f.title}  [cyan]{', '.join(f.soc2)}[/]  [dim]{f.file or 'project-wide'}[/]")

    if new:
        console.print("\n[bold red]✘ Commit blocked:[/] this change introduces compliance violations. "
                      "Fix them, or run [bold]python -m auditbot fix[/] to apply verified fixes. "
                      "Skipping the hook won't help: the same gate runs in CI on every pull request.")
        return 1
    console.print("\n[bold green]✔ No new compliance violations.[/]")
    return 0


def cmd_install_hook(a):
    root = Path(a.path).resolve()
    hook = root / ".git" / "hooks" / "pre-commit"
    if not hook.parent.exists():
        console.print(f"[red]{root} is not a git repository[/]")
        return 2
    proj = Path(__file__).resolve().parent.parent.as_posix()
    py = Path(sys.executable).as_posix()
    hook.write_text(
        "#!/bin/sh\n# Audit Readiness Bot compliance gate\n"
        f'AUDITBOT_COLOR=1 PYTHONIOENCODING=utf-8 PYTHONPATH="{proj}" "{py}" -m auditbot check "$(git rev-parse --show-toplevel)" --staged\n',
        encoding="utf-8", newline="\n")
    hook.chmod(0o755)
    console.print(f"[green]✔ pre-commit hook installed:[/] {hook}")
    return 0


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    p = argparse.ArgumentParser(prog="audit-bot", description="Automated evidence collector & audit readiness bot")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="full readiness scan + evidence + report")
    s.add_argument("path", help="local folder or a public git URL (https://github.com/...)")
    s.add_argument("--out", default="audit-output")
    s.add_argument("--no-ai", action="store_true")
    s.set_defaults(fn=cmd_scan)
    c = sub.add_parser("check", help="flag violations introduced by a change")
    c.add_argument("path")
    c.add_argument("--staged", action="store_true", help="check staged changes (pre-commit)")
    c.add_argument("--base", default="HEAD", help="git ref to compare against (e.g. origin/main in CI)")
    c.add_argument("--no-ai", action="store_true")
    c.set_defaults(fn=cmd_check)
    x = sub.add_parser("fix", help="apply verified fixes (each one re-scanned before it is kept)")
    x.add_argument("path")
    x.add_argument("--rule", action="append", help="only fix this rule ID (repeatable)")
    x.add_argument("--dry-run", action="store_true", help="show the diff without changing files")
    x.add_argument("--no-ai", action="store_true")
    x.set_defaults(fn=cmd_fix)
    h = sub.add_parser("install-hook", help="install git pre-commit gate")
    h.add_argument("path")
    h.set_defaults(fn=cmd_install_hook)
    for sp in (s, c, x):
        sp.add_argument("--online", action="store_true",
                        help="also ask PyPI/npm whether each dependency exists and how new it is "
                             "(catches hallucinated packages; same as AUDITBOT_ONLINE=1)")
    a = p.parse_args()
    if getattr(a, "online", False):
        os.environ["AUDITBOT_ONLINE"] = "1"
    sys.exit(a.fn(a))


if __name__ == "__main__":
    main()
