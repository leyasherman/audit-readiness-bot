# Audit Readiness Bot — hackathon project (2h)

Python CLI that scans IaC/config, maps findings to SOC 2 + ISO 27001:2022 controls, outputs audit evidence, and blocks commits that introduce violations.

## Layout
- `auditbot/scanner.py` — rules engine. Works on in-memory `{path: text}` (working tree, git index, or any rev). Each rule returns `(applicable, findings)`; score = passed / applicable tests.
- `auditbot/supplychain.py` — DEP-TYPOSQUAT (vibe-coding / slopsquatting): parses requirements*.txt, pyproject.toml, package.json; offline checks against embedded popular-package lists (known squats, import-name-as-package like `sklearn`, separator/look-alike variants, impersonation affixes, 1–2 keystroke typos). `--online` / `AUDITBOT_ONLINE=1` also asks PyPI/npm (not found → hallucinated; <90 days old → verify); cached 24h in `.auditbot-cache/registry.json`, network errors ignored. False positive → `# auditbot: allow` on the line, or `"auditbot": {"allow": [...]}` in package.json.
- Other vibe-coding checks in scanner.py: AI-AGENT-CONTEXT (injection phrases in AGENTS.md/CLAUDE.md/.cursorrules…, invisible Unicode anywhere), APP-INSECURE-CONFIG now also covers SQL/shell built from strings, XSS sinks, TLS/JWT verification off, client-side auth; SECRET-HARDCODED covers OpenAI/Anthropic/GitHub/Stripe/Slack/Google keys and DB URLs with inline passwords.
- `demo/vibe-coded-app/` — fictional AI-generated app with planted typosquats, a hallucinated package, prompt injection and SQLi: `scan demo/vibe-coded-app [--online]` (37%, 9 findings offline; +1 online). New rules are N/A on demo-target, so 78/42/86 are unchanged.
- `auditbot/controls.yaml` — rule → SOC 2 / ISO IDs, severity, default risk/fix text. **Control IDs live only here; never let the LLM invent them.**
- `auditbot/enrich.py` — one batched Claude call (`claude-opus-5-5`, effort low, JSON schema output) for risk/remediation/executive summary. Falls back to catalog text without `ANTHROPIC_API_KEY` or on any error. Caches in `.auditbot-cache/`.
- `auditbot/report.py` + `templates/report.html` — Rich dashboard, `evidence.json` (sha256 per file, git commit), HTML brief.
  - `report.html` has 3 tabs (`#lab`, `#pipeline` hashes): Report · Readiness Lab (playable what-if, same weights/rounding as `ScanResult.score`) · Agent Pipeline (mocked PR→agents→CI→Prometheus→delta→gate run; static scores 78/42/86 computed from the scan). Partials: `templates/_interactive.css`, `_lab.*`, `_pipeline.*`, `_fx.js`, `_wow.js` (Auditus branding, auditor's stamp, Proof Mode hover-to-explain on Report numbers) (pulled in via `{% include %}`, so never write `{{`, `{%` or `{#` in them).
  - `report_classic.html` → `report-classic.html`: the single-page version without tabs, kept for print/email.
- `auditbot/__main__.py` — CLI: `scan <dir|git URL>`, `check [--staged|--base REF]`, `fix [--dry-run] [--rule ID]`, `install-hook`.
- `auditbot/fixer.py` — verified auto-remediation: Claude patch (or offline template) → apply in memory → re-scan → keep only if the finding is gone and nothing new appears.
- Score is severity-weighted (critical 10 / high 5 / medium 2 / low 1) over applicable tests.
- `demo-target/` — fictional "Acme Health" repo (own git repo). Baseline = 78% (3 planted gaps: IAM wildcard, no MFA, no CloudTrail).
- `demo/risky_change.py` — simulates a bad commit (SSH 0.0.0.0/0, DB encryption off, AWS key) → gate blocks, 78% → 42%; `fix` → 86%, commit passes.
- `tests/` — `python -m unittest -v`; DemoTests pin the demo numbers (78 / 42 / 86).

## Run
- Setup: `powershell -ExecutionPolicy Bypass -File setup.ps1`
- `.venv\Scripts\python -m auditbot scan demo-target`
- `.venv\Scripts\python demo\risky_change.py` then `cd demo-target; git add -A; git commit -m "quick fix"` → blocked
- `.venv\Scripts\python -m auditbot fix demo-target` then commit again → passes
- Reset demo: `.venv\Scripts\python demo\setup_demo.py`

## Rules for changes
- Adding a rule: write `rule_x(files)` in scanner.py, register in `RULES`, add entry in controls.yaml.
- Keep the demo path working at all times; re-run the demo after every change.
- The Claude layer must never break the gate (always fall back).
- Not yet verified: Claude enrichment and Claude-written fix patches with a real key; the GitHub Action running on GitHub.
- `demo/build_site.py` rebuilds `docs/` (GitHub Pages demo: report of demo-target + a "fictional data" banner). Re-run it after changing the report templates.
- Changing demo-target's tracked files: delete `demo-target/.git` and re-run setup_demo.py, otherwise the reset reverts them.

## Ideas if time remains
`--json` output for CI, more rules (K8s manifests, Dockerfile USER), treat `examples/` paths as lower severity, CloudTrail N/A for reusable modules.
