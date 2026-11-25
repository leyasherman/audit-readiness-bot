"""Verified auto-remediation.

For each finding we propose a patch, apply it in memory, re-scan, and keep it only if the targeted
violation disappears AND no new violation appears. Claude writes the patch when an API key is set;
built-in templates cover the common cases offline, so the fix flow works on stage without Wi-Fi.
Nothing is written to disk unless the re-scan proves the fix."""
from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass

from .enrich import CACHE_DIR, MODEL
from .scanner import Finding, scan

CLOUDTRAIL_TF = '''
# ---------- Audit logging (added by audit-bot fix) ----------
resource "aws_s3_bucket" "audit_logs" {
  bucket = "audit-logs-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "audit_logs" {
  bucket                  = aws_s3_bucket.audit_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_caller_identity" "current" {}

resource "aws_cloudtrail" "main" {
  name                          = "org-audit-trail"
  s3_bucket_name                = aws_s3_bucket.audit_logs.id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
}
'''


@dataclass
class Fix:
    finding: Finding
    path: str
    new_text: str
    summary: str
    source: str  # "template" | model name


# ---------------------------------------------------------------- offline templates

def _replace_line(text: str, line: int, old: str, new: str) -> str | None:
    lines = text.split("\n")
    if not line or line > len(lines) or old not in lines[line - 1]:
        return None
    lines[line - 1] = lines[line - 1].replace(old, new, 1)
    return "\n".join(lines)


def _tpl_cloudtrail(files, f):
    tf = [p for p in files if p.endswith(".tf")]
    path = next((p for p in tf if 'provider "aws"' in files[p]), tf[0] if tf else None)
    if not path:
        return None
    return path, files[path].rstrip("\n") + "\n" + CLOUDTRAIL_TF, \
        "Added a multi-region CloudTrail with log file validation, writing to an encrypted, private S3 bucket."


def _tpl_db_encryption(files, f):
    text = files[f.file]
    new = _replace_line(text, f.line, "false", "true")
    if new is None:  # attribute missing: insert it after the resource header
        lines = text.split("\n")
        lines.insert(f.line, "  storage_encrypted = true")
        new = "\n".join(lines)
    return f.file, new, "Enabled storage encryption at rest on the database."


def _tpl_open_admin(files, f):
    new = _replace_line(files[f.file], f.line, "0.0.0.0/0", "10.0.0.0/8")
    return (f.file, new, "Restricted admin access from the whole internet to the private network (10.0.0.0/8). "
                         "Narrow this to your VPN/bastion range.") if new else None


def _tpl_secret(files, f):
    text = files[f.file]
    if not f.file.endswith(".py"):
        return None
    m = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*[\"'][^\"']+[\"']\s*$", f.snippet)
    if not m:
        return None
    var = m.group(1)
    new = _replace_line(text, f.line, f.snippet, f'{var} = os.environ["{var}"]')
    if new is None:
        return None
    if not re.search(r"(?m)^import os\b", new):
        new = "import os\n" + new
    return f.file, new, (f"Moved {var} out of the source code into an environment variable. "
                         "Still rotate the key: treat any secret that was ever typed into code as exposed.")


def _tpl_dependency(files, f):
    """Swap a typosquatted / hallucinated dependency for the package the detector says was meant."""
    bad, good = re.match(r"'([^']+)'", f.detail), re.search(r"Did you mean '([^']+)'\?", f.detail)
    if not (bad and good):
        return None  # e.g. 'not on PyPI': no safe automatic replacement, a human must pick the package
    bad, good = bad.group(1), good.group(1)
    if f.file.endswith("package.json") and "[" in good:
        return None
    new_line = re.sub(r"(?<![A-Za-z0-9_.@/-])" + re.escape(bad) + r"(?![A-Za-z0-9_-])", lambda _: good, f.snippet, count=1)
    if new_line == f.snippet:
        return None
    new = _replace_line(files[f.file], f.line, f.snippet, new_line)
    if new is None:
        return None
    return f.file, new, (f"Replaced '{bad}' with '{good}'. If '{bad}' was ever installed (laptops, CI runners), "
                         "check what it ran at install time and rotate credentials on those machines.")


TEMPLATES = {
    "DEP-TYPOSQUAT": _tpl_dependency,
    "LOG-AUDIT-TRAIL": _tpl_cloudtrail,
    "DB-ENCRYPTION": _tpl_db_encryption,
    "NET-OPEN-ADMIN": _tpl_open_admin,
    "SECRET-HARDCODED": _tpl_secret,
}

# ---------------------------------------------------------------- Claude patches

AI_SCHEMA = {
    "type": "object",
    "properties": {"content": {"type": "string"}, "summary": {"type": "string"}},
    "required": ["content", "summary"],
    "additionalProperties": False,
}

AI_SYSTEM = (
    "You are a cloud security engineer fixing compliance violations found by a scanner. "
    "You receive one file and the findings in it. Return the COMPLETE corrected file in `content`: "
    "fix only the listed findings with the smallest safe change, keep everything else byte-for-byte identical, "
    "and never introduce secrets or open network access. If a value needs a human decision (e.g. a VPN CIDR), "
    "use a conservative private default and say so. `summary`: one or two sentences on what you changed and why."
)


def _ai_patch(path: str, text: str, findings: list[Finding]) -> tuple[str, str] | None:
    if not (os.getenv("ANTHROPIC_API_KEY") or os.getenv("ANTHROPIC_AUTH_TOKEN")):
        return None
    payload = [{"rule": f.rule, "title": f.title, "line": f.line, "snippet": f.snippet, "detail": f.detail}
               for f in findings]
    key = hashlib.sha256(json.dumps([MODEL, "fix", path, text, payload]).encode()).hexdigest()[:16]
    cache = CACHE_DIR / f"fix-{key}.json"
    if cache.exists():
        d = json.loads(cache.read_text(encoding="utf-8"))
        return d["content"], d["summary"]
    try:
        import anthropic

        client = anthropic.Anthropic(timeout=120, max_retries=1)
        resp = client.messages.create(
            model=MODEL, max_tokens=32000, system=AI_SYSTEM,
            messages=[{"role": "user", "content":
                       f"File: {path}\nFindings:\n{json.dumps(payload, indent=1)}\n\n--- FILE START ---\n{text}\n--- FILE END ---"}],
            output_config={"effort": "low", "format": {"type": "json_schema", "schema": AI_SCHEMA}},
        )
        if resp.stop_reason != "end_turn":
            return None
        d = json.loads(next(b.text for b in resp.content if b.type == "text"))
        CACHE_DIR.mkdir(exist_ok=True)
        cache.write_text(json.dumps(d, indent=2), encoding="utf-8")
        return d["content"], d["summary"]
    except Exception:
        return None  # the fix flow must never crash; fall back to templates


# ---------------------------------------------------------------- verification loop

def _verified(files, new_files, targets) -> list[Finding]:
    """Return the targeted findings this change removes, or [] if it removes none or adds any new violation."""
    before = {f.key() for f in scan(files).findings}
    after = {f.key() for f in scan(new_files).findings}
    if after - before:
        return []
    return [f for f in targets if f.key() not in after]


def plan_fixes(files: dict[str, str], use_ai: bool = True, rules: set[str] | None = None):
    """Return (fixes, unfixed findings, final files). Each fix is applied on top of the previous ones."""
    files = dict(files)
    todo = [f for f in scan(files).findings if not rules or f.rule in rules]
    fixes, done = [], set()

    if use_ai:
        by_file: dict[str, list[Finding]] = {}
        for f in todo:
            if f.file:
                by_file.setdefault(f.file, []).append(f)
        for path, fs in by_file.items():
            patch = _ai_patch(path, files[path], fs)
            if not patch:
                continue
            new_files = {**files, path: patch[0]}
            for f in _verified(files, new_files, fs):
                fixes.append(Fix(f, path, patch[0], patch[1], MODEL))
                done.add(f.key())
            if any(x.key() in done for x in fs):
                files = new_files

    for f in todo:
        if f.key() in done or f.rule not in TEMPLATES:
            continue
        # Line numbers move after earlier patches: re-locate the finding in the current files.
        cur = next((c for c in scan(files).findings if c.key() == f.key()), None)
        if not cur:
            continue
        res = TEMPLATES[f.rule](files, cur)
        if not res or not res[1]:
            continue
        path, new_text, summary = res
        new_files = {**files, path: new_text}
        if _verified(files, new_files, [cur]):
            fixes.append(Fix(cur, path, new_text, summary, "template"))
            done.add(f.key())
            files = new_files

    unfixed = [f for f in todo if f.key() not in done]
    return fixes, unfixed, files
