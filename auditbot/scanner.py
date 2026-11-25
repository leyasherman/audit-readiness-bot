"""Static rules engine: files in -> findings out. Works on in-memory {path: text} so it can
scan the working tree, the git index, or any past commit the same way."""
from __future__ import annotations

import hashlib
import re
import subprocess
from dataclasses import dataclass, field, asdict
from pathlib import Path

import yaml

from . import supplychain
from .supplychain import is_manifest

CONTROLS = yaml.safe_load((Path(__file__).parent / "controls.yaml").read_text(encoding="utf-8"))

SCAN_EXT = {".tf", ".yml", ".yaml", ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".vue", ".json", ".env",
            ".php", ".java", ".rb", ".go", ".cs", ".properties", ".ini", ".cfg", ".conf", ".toml"}
# Instruction files that AI coding agents read as trusted context: a prompt-injection target.
AGENT_FILES = {"agents.md", "claude.md", "gemini.md", ".cursorrules", ".windsurfrules", ".clinerules", "copilot-instructions.md"}
AGENT_PATH = re.compile(r"(^|/)(\.cursor/rules|\.github/prompts|\.claude/(commands|agents))/", re.I)
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".terraform", "audit-output"}
# Tests, fixtures and vendored third-party code: fake credentials and minified libraries there are noise,
# and they don't ship to production. Auditors scope them out too.
SKIP_PATH = re.compile(r"(^|/)(tests?|__tests__|specs?|fixtures?|e2e|cypress|vendor|third_party|libs)(/|$)"
                       r"|(^|/)src/it/|\.(spec|test)\.[jt]sx?$|\.min\.js$|(^|/)test_[^/]+\.py$", re.I)


@dataclass
class Finding:
    rule: str
    file: str | None
    line: int | None
    snippet: str
    detail: str
    id: str = ""
    severity: str = ""
    title: str = ""
    soc2: list = field(default_factory=list)
    iso27001: list = field(default_factory=list)

    def key(self):
        # Stable across line shifts: used to diff two scans.
        return (self.rule, self.file, re.sub(r"\s+", " ", self.snippet).strip())

    def to_dict(self):
        return asdict(self)


# ---------------------------------------------------------------- file sources

def _wanted(path: str) -> bool:
    p = Path(path)
    if any(part in SKIP_DIRS for part in p.parts) or SKIP_PATH.search(path):
        return False
    return (p.suffix in SCAN_EXT or p.name.startswith(".env") or p.name.startswith("docker-compose")
            or is_manifest(path) or is_agent_file(path))


def is_agent_file(path: str) -> bool:
    return Path(path).name.lower() in AGENT_FILES or bool(AGENT_PATH.search(path))


def files_from_dir(root: Path) -> dict[str, str]:
    out = {}
    for f in root.rglob("*"):
        rel = f.relative_to(root).as_posix()
        if f.is_file() and _wanted(rel):
            try:
                out[rel] = f.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                pass
    return out


def git(root: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True,
                          encoding="utf-8", check=True).stdout


def files_from_rev(root: Path, rev: str) -> dict[str, str]:
    """rev='' reads the staging index (what is about to be committed)."""
    names = git(root, "ls-files") if rev == "" else git(root, "ls-tree", "-r", "--name-only", rev)
    out = {}
    for name in names.splitlines():
        if _wanted(name):
            try:
                out[name] = git(root, "show", f"{rev}:{name}")
            except subprocess.CalledProcessError:
                pass
    return out


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------- helpers

def _line_of(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


def _line_text(text: str, line: int) -> str:
    return text.splitlines()[line - 1].strip() if line else ""


def _blocks(text: str, header: str):
    """Yield (match, body, body_offset) for HCL blocks whose header matches regex `header`."""
    for m in re.finditer(header + r"\s*\{", text):
        depth, i = 1, m.end()
        while i < len(text) and depth:
            c = text[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
            i += 1
        yield m, text[m.end():i - 1], m.end()


def _resources(files, rtype):
    for path, text in files.items():
        if path.endswith(".tf"):
            for m, body, off in _blocks(text, rf'resource\s+"{rtype}"\s+"([\w-]+)"'):
                yield path, text, m, body, off


def _find(rule, path, text, idx, detail):
    line = _line_of(text, idx)
    return Finding(rule, path, line, _line_text(text, line), detail)


def _tf(files):
    return {p: t for p, t in files.items() if p.endswith(".tf")}


# ---------------------------------------------------------------- rules
# Each rule returns (applicable, [findings]). Not-applicable tests don't count toward the score.

SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS access key ID"),
    # header followed by actual key material (not just the header string used in parsing code)
    (r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----(?:\\r|\\n|\s)*[A-Za-z0-9+/]{40}", "Private key"),
    # password-like names (incl. db_password, $db_password): any non-placeholder value of 3+ chars
    (r"(?i)\b(?:[a-z0-9]+_)*(password|passwd|pwd|secret)\b\s*(?:[:=]|=>)\s*[\"']([^\"'\s$]{3,})[\"']",
     "Hardcoded credential"),
    # token / API-key names: only values that look like real keys (16+ chars incl. a digit), so
    # identifiers such as token: "keyword" in editor/highlighter code are not flagged
    (r"(?i)\b(?:[a-z0-9]+_)*(api_?key|token|access_?key|secret_?key|aws_secret_access_key)\b\s*(?:[:=]|=>)\s*"
     r"[\"'](?=[^\"']*\d)([A-Za-z0-9_\-+/=.]{16,})[\"']",
     "Hardcoded API key or token"),
    (r"(?im)^\s*(?:[A-Z_]*(?:PASSWORD|SECRET|API_KEY|TOKEN))\s*=\s*(?!\$|<|changeme|example)([^\s#]{6,})\s*$",
     "Hardcoded credential in env file"),
    # provider key formats that AI snippets paste inline, whatever the variable is called
    (r"\bsk-ant-[A-Za-z0-9_\-]{20,}", "Anthropic API key"),
    (r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}", "OpenAI API key"),
    (r"\bgh[pousr]_[A-Za-z0-9]{36,}", "GitHub token"),
    (r"\b[sr]k_live_[A-Za-z0-9]{20,}", "Stripe live key"),
    (r"\bxox[abprs]-[A-Za-z0-9-]{10,}", "Slack token"),
    (r"\bAIza[0-9A-Za-z_\-]{35}", "Google API key"),
    # connection string with an inline password (placeholders like ${VAR} or <password> are skipped)
    (r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql)://[^:/\s\"'@]+:([^@\s\"'/$<{]{3,})@",
     "Database URL with inline password"),
]


PLACEHOLDERS = {"changeme", "change_me", "password", "secret", "example", "xxx", "xxxx", "xxxxxx", "***",
                "******", "none", "null", "todo", "redacted", "your_password", "yourpassword", "dummy"}


def rule_secrets(files):
    out = []
    for path, text in files.items():
        for pat, label in SECRET_PATTERNS:
            if "env file" in label and not Path(path).name.startswith(".env"):
                continue
            if Path(path).name.endswith(".example"):
                continue
            for m in re.finditer(pat, text):
                if m.lastindex and m.group(m.lastindex).lower() in PLACEHOLDERS:
                    continue
                out.append(_find("SECRET-HARDCODED", path, text, m.start(), f"{label} found"))
    # one finding per line
    uniq = {(f.file, f.line): f for f in out}
    return bool(files), list(uniq.values())


def rule_s3_encryption(files):
    tf = _tf(files)
    all_tf = "\n".join(tf.values())
    out, any_bucket = [], False
    for path, text, m, body, off in _resources(tf, "aws_s3_bucket"):
        any_bucket = True
        name = m.group(1)
        if "server_side_encryption_configuration" in body:
            continue
        if re.search(rf"aws_s3_bucket_server_side_encryption_configuration[\s\S]*?aws_s3_bucket\.{name}\b", all_tf):
            continue
        out.append(_find("S3-ENCRYPTION", path, text, m.start(), f"Bucket '{name}' has no server-side encryption"))
    return any_bucket, out


def rule_s3_public(files):
    tf = _tf(files)
    out = []
    for path, text in tf.items():
        for m in re.finditer(r'acl\s*=\s*"public-read(-write)?"', text):
            out.append(_find("S3-PUBLIC", path, text, m.start(), "Bucket ACL grants public access"))
        for m in re.finditer(r"(block_public_acls|block_public_policy|restrict_public_buckets|ignore_public_acls)\s*=\s*false", text):
            out.append(_find("S3-PUBLIC", path, text, m.start(), f"{m.group(1)} disabled"))
    applicable = any("aws_s3_bucket" in t for t in tf.values())
    return applicable, out


def _ports_cover(body, ports=(22, 3389)):
    fp = re.search(r"from_port\s*=\s*(-?\d+)", body)
    tp = re.search(r"to_port\s*=\s*(-?\d+)", body)
    if not fp:
        return False
    lo, hi = int(fp.group(1)), int(tp.group(1)) if tp else int(fp.group(1))
    if lo == -1 or (lo == 0 and hi in (0, 65535)):
        return True
    return any(lo <= p <= hi for p in ports)


def rule_open_admin(files):
    tf = _tf(files)
    out, applicable = [], False
    for path, text in tf.items():
        candidates = list(_blocks(text, r"\bingress"))
        candidates += [(m, b, o) for m, b, o in _blocks(text, r'resource\s+"aws_security_group_rule"\s+"[\w-]+"')
                       if re.search(r'type\s*=\s*"ingress"', b)]
        candidates += list(_blocks(text, r'resource\s+"aws_vpc_security_group_ingress_rule"\s+"[\w-]+"'))
        for m, body, off in candidates:
            applicable = True
            cidr = re.search(r'"0\.0\.0\.0/0"', body)
            if cidr and _ports_cover(body):
                port = re.search(r"from_port\s*=\s*(-?\d+)", body).group(1)
                out.append(_find("NET-OPEN-ADMIN", path, text, off + cidr.start(),
                                 f"Port {port} reachable from 0.0.0.0/0"))
    return applicable, out


def rule_db_encryption(files):
    out, applicable = [], False
    for rtype in ("aws_db_instance", "aws_rds_cluster"):
        for path, text, m, body, off in _resources(_tf(files), rtype):
            applicable = True
            bad = re.search(r"storage_encrypted\s*=\s*false", body)
            if bad:
                out.append(_find("DB-ENCRYPTION", path, text, off + bad.start(), f"{rtype}.{m.group(1)} encryption disabled"))
            # Set via a variable/expression = configurable, can't prove it's off: don't flag.
            elif not re.search(r"storage_encrypted\s*=", body):
                out.append(_find("DB-ENCRYPTION", path, text, m.start(), f"{rtype}.{m.group(1)} missing storage_encrypted"))
    return applicable, out


def rule_db_public(files):
    out, applicable = [], False
    for rtype in ("aws_db_instance", "aws_rds_cluster_instance"):
        for path, text, m, body, off in _resources(_tf(files), rtype):
            applicable = True
            bad = re.search(r"publicly_accessible\s*=\s*true", body)
            if bad:
                out.append(_find("DB-PUBLIC", path, text, off + bad.start(), f"{rtype}.{m.group(1)} is publicly accessible"))
    return applicable, out


def rule_iam_wildcard(files):
    out = []
    pats = [r'"?Action"?\s*[:=]\s*\[?\s*"\*"', r'actions\s*=\s*\[\s*"\*"\s*\]']
    for path, text in files.items():
        if not (path.endswith(".tf") or path.endswith(".json")):
            continue
        for pat in pats:
            for m in re.finditer(pat, text):
                out.append(_find("IAM-WILDCARD", path, text, m.start(), "IAM policy allows all actions (*)"))
    applicable = any(re.search(r"aws_iam_|\"Action\"", t) for t in files.values())
    return applicable, out


def rule_iam_mfa(files):
    tf = _tf(files)
    iam = [(p, t, m) for p, t in tf.items() for m in re.finditer(r'resource\s+"aws_iam_(user|group|policy|group_policy)"', t)]
    if not iam:
        return False, []
    if any("aws:MultiFactorAuthPresent" in t for t in files.values()):
        return True, []
    p, t, m = iam[0]
    return True, [_find("IAM-MFA", p, t, m.start(), "No IAM policy enforces aws:MultiFactorAuthPresent")]


def rule_cloudtrail(files):
    tf = _tf(files)
    if not tf:
        return False, []
    if any(re.search(r'resource\s+"aws_cloudtrail"', t) for t in tf.values()):
        return True, []
    return True, [Finding("LOG-AUDIT-TRAIL", None, None, "(project-wide)", "No aws_cloudtrail resource defined in infrastructure")]


APP_PATTERNS = [
    (r"(?m)^\s*DEBUG\s*[:=]\s*(True|true|1|\"true\")\b", "Debug mode enabled"),
    (r"allow_origins\s*=\s*\[\s*[\"']\*[\"']\s*\]", "CORS allows any origin"),
    (r"CORS\([^)]*origins\s*=\s*[\"']\*[\"']", "CORS allows any origin"),
    (r"Access-Control-Allow-Origin[\"']?\s*[:,]\s*[\"']\*[\"']", "CORS allows any origin"),
    (r"origin\s*:\s*[\"']\*[\"']", "CORS allows any origin"),
    # insecure logic that AI assistants produce to "make it work": high-signal patterns only
    (r"\.execute(?:many)?\(\s*f(\"|')(?:(?!\1).)*?\{", "SQL query built with an f-string (SQL injection)"),
    (r"\.execute(?:many)?\(\s*(\"|')(?:(?!\1).)*\1\s*(?:%|\+)\s*[A-Za-z_(]", "SQL query built by string concatenation (SQL injection)"),
    (r"(?:os\.system|os\.popen|subprocess\.\w+)\(\s*f(\"|')(?:(?!\1).)*?\{", "Shell command built from an f-string (command injection)"),
    (r"\b(?:eval|exec)\(\s*(?:request|req|input|params|body)\b", "eval/exec on user input (code injection)"),
    (r"\bverify\s*=\s*False\b", "TLS certificate verification disabled"),
    (r"rejectUnauthorized\s*:\s*false", "TLS certificate verification disabled"),
    (r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']?0", "TLS certificate verification disabled"),
    (r"[\"']verify_signature[\"']\s*:\s*False|algorithms\s*=\s*\[\s*[\"']none[\"']", "JWT signature verification disabled"),
    (r"dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:\s*(?![\"'`])", "Unsanitized HTML injected into the page (XSS)"),
    (r"\.innerHTML\s*=\s*(?![\"'`]|\s*$)[A-Za-z_$]", "innerHTML assigned from a variable (XSS)"),
    (r"\b(?:mark_safe|Markup)\(\s*(?:f[\"']|request\b)", "User data marked as safe HTML (XSS)"),
    (r"localStorage\.(?:setItem|getItem)\(\s*[\"'](?:isAdmin|is_admin|isAuthenticated|isLoggedIn|role|userRole)[\"']",
     "Authorization decided by client-side storage (bypassable)"),
]
APP_EXT = {".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".vue", ".env"}


def rule_app_config(files):
    out, applicable = [], False
    pats = APP_PATTERNS
    for path, text in files.items():
        if Path(path).suffix in APP_EXT or Path(path).name.startswith(".env"):
            applicable = True
            for pat, label in pats:
                for m in re.finditer(pat, text):
                    out.append(_find("APP-INSECURE-CONFIG", path, text, m.start(), label))
    return applicable, out


def rule_containers(files):
    out, applicable = [], False
    for path, text in files.items():
        if not Path(path).name.startswith("docker-compose"):
            continue
        applicable = True
        for m in re.finditer(r"privileged:\s*true", text):
            out.append(_find("CONTAINER-HARDENING", path, text, m.start(), "Container runs privileged"))
        for m in re.finditer(r"user:\s*[\"']?(root|0)[\"']?\s*$", text, re.M):
            out.append(_find("CONTAINER-HARDENING", path, text, m.start(), "Container runs as root"))
        for m in re.finditer(r"network_mode:\s*[\"']?host", text):
            out.append(_find("CONTAINER-HARDENING", path, text, m.start(), "Container uses host network"))
        for m in re.finditer(r"[\"']?(?:\d+\.\d+\.\d+\.\d+:)?\d+:(5432|3306|6379|27017)[\"']?", text):
            out.append(_find("CONTAINER-HARDENING", path, text, m.start(), f"Database port {m.group(1)} published to host"))
    return applicable, out


def rule_dependencies(files):
    """Typosquatted / hallucinated dependencies (see supplychain.py). N/A without a dependency manifest."""
    out, deps = [], []
    for path, text in files.items():
        if is_manifest(path):
            for eco, name, idx, allowed in supplychain.dependencies(path, text):
                deps.append((path, text, eco, name, idx, allowed))
    flagged = set()
    for path, text, eco, name, idx, allowed in deps:
        verdict = None if allowed else supplychain.offline_verdict(eco, name)
        if verdict:
            out.append(_find("DEP-TYPOSQUAT", path, text, idx, verdict[0]))
            flagged.add((path, name))
    if supplychain.online_enabled():
        todo = {(eco, supplychain.normalize(eco, name)) for path, _, eco, name, _, allowed in deps
                if not allowed and (path, name) not in flagged}
        info = supplychain.lookup(todo)
        for path, text, eco, name, idx, allowed in deps:
            key = (eco, supplychain.normalize(eco, name))
            if allowed or (path, name) in flagged or key not in info:
                continue
            detail = supplychain.online_verdict(eco, name, info[key])
            if detail:
                out.append(_find("DEP-TYPOSQUAT", path, text, idx, detail))
    return bool(deps), out


# bidi overrides (Trojan Source), zero-width space/non-joiner, word joiner, Unicode tag characters
# ("ASCII smuggling"). U+200D is left out: emoji sequences use it legitimately.
HIDDEN_CHARS = re.compile("[‪-‮⁦-⁩​‌⁠\U000e0000-\U000e007f]")
INJECTION = [
    r"(?i)\b(?:ignore|disregard|forget)\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|earlier|system)\s+(?:instructions|prompts?|rules)",
    r"(?i)\b(?:do\s+not|don'?t|never)\s+(?:tell|inform|mention\s+(?:this\s+)?to|alert|notify)\s+the\s+user",
    r"(?i)\bwithout\s+(?:telling|asking|notifying|informing)\s+the\s+user",
    r"(?i)\b(?:curl|wget)\b[^\n|]*\|\s*(?:ba|z)?sh\b",
    r"(?i)\b(?:send|post|upload|exfiltrate)\b[^\n]{0,60}\b(?:\.env|secrets?|credentials|api[_ ]?keys?|ssh\s+keys?|tokens?)\b[^\n]{0,40}\bhttps?://",
]


def rule_agent_context(files):
    """Prompt-injection surface: instructions planted in files AI agents trust, or hidden from reviewers.
    N/A when the repo has no agent instruction files and no invisible characters anywhere."""
    out = []
    agent = [p for p in files if is_agent_file(p)]
    for path, text in files.items():
        m = HIDDEN_CHARS.search(text)
        if m:
            out.append(_find("AI-AGENT-CONTEXT", path, text, m.start(),
                             f"Invisible Unicode character U+{ord(m.group()):04X}: text a reviewer can't see but a model or compiler reads"))
    for path in agent:
        text = files[path]
        for pat in INJECTION:
            for m in re.finditer(pat, text):
                out.append(_find("AI-AGENT-CONTEXT", path, text, m.start(), "Instruction-injection phrase in an AI agent context file"))
    uniq = {(f.file, f.line): f for f in out}
    return bool(agent) or bool(out), list(uniq.values())


RULES = {
    "SECRET-HARDCODED": rule_secrets,
    "DEP-TYPOSQUAT": rule_dependencies,
    "AI-AGENT-CONTEXT": rule_agent_context,
    "S3-ENCRYPTION": rule_s3_encryption,
    "S3-PUBLIC": rule_s3_public,
    "NET-OPEN-ADMIN": rule_open_admin,
    "DB-ENCRYPTION": rule_db_encryption,
    "DB-PUBLIC": rule_db_public,
    "IAM-WILDCARD": rule_iam_wildcard,
    "IAM-MFA": rule_iam_mfa,
    "LOG-AUDIT-TRAIL": rule_cloudtrail,
    "APP-INSECURE-CONFIG": rule_app_config,
    "CONTAINER-HARDENING": rule_containers,
}

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
# Risk-weighted score: a leaked credential must hurt far more than a debug flag.
SEV_WEIGHT = {"critical": 10, "high": 5, "medium": 2, "low": 1}


@dataclass
class ScanResult:
    files: dict
    findings: list
    tests: list  # [{id,title,status,soc2,iso27001,severity,count}]

    @property
    def score(self) -> int:
        """Severity-weighted share of applicable control tests that pass (0-100)."""
        evaluated = [t for t in self.tests if t["status"] != "N/A"]
        total = sum(SEV_WEIGHT[t["severity"]] for t in evaluated)
        if not total:
            return 100
        return round(100 * sum(SEV_WEIGHT[t["severity"]] for t in evaluated if t["status"] == "PASS") / total)


def scan(files: dict[str, str]) -> ScanResult:
    findings, tests = [], []
    for rule_id, fn in RULES.items():
        meta = CONTROLS[rule_id]
        applicable, found = fn(files)
        for f in found:
            f.severity, f.title = meta["severity"], meta["title"]
            f.soc2, f.iso27001 = meta["soc2"], meta["iso27001"]
        findings += found
        tests.append({
            "id": rule_id, "title": meta["title"], "severity": meta["severity"],
            "soc2": meta["soc2"], "iso27001": meta["iso27001"], "count": len(found),
            "status": "N/A" if not applicable else ("FAIL" if found else "PASS"),
        })
    findings.sort(key=lambda f: (SEV_ORDER[f.severity], f.file or "", f.line or 0))
    for i, f in enumerate(findings, 1):
        f.id = f"F-{i:03d}"
    return ScanResult(files, findings, tests)
