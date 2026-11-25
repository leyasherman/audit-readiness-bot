"""Claude writes the human text (risk, remediation, executive brief). Detection and control IDs
stay deterministic. Falls back to the static catalog text if no API key / no network, and caches
responses so the live demo never waits twice or breaks on bad Wi-Fi."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from .scanner import CONTROLS

MODEL = os.getenv("AUDITBOT_MODEL", "claude-opus-5-5")
CACHE_DIR = Path(__file__).parent.parent / ".auditbot-cache"

SCHEMA = {
    "type": "object",
    "properties": {
        "executive_summary": {"type": "string"},
        "top_risks": {"type": "array", "items": {"type": "string"}},
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "risk_explanation": {"type": "string"},
                    "remediation": {"type": "string"},
                    "auditor_note": {"type": "string"},
                },
                "required": ["id", "risk_explanation", "remediation", "auditor_note"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["executive_summary", "top_risks", "findings"],
    "additionalProperties": False,
}

SYSTEM = (
    "You are a GRC analyst preparing SOC 2 Type II and ISO 27001 audit evidence. "
    "You receive findings from a deterministic scanner; the control IDs are already correct, do not change or add any. "
    "For each finding write: risk_explanation (1-2 sentences, business impact, concrete to this code), "
    "remediation (specific fix, include a short code snippet in the same language as the file when useful), "
    "auditor_note (one sentence on what evidence an auditor will expect once fixed). "
    "executive_summary: 3-4 sentences for a non-technical executive: readiness, biggest exposure, what to fix first. "
    "top_risks: at most 3 short bullet strings. Be precise; no filler."
)


def _fallback(findings, score, context):
    worst = [f for f in findings if f["severity"] == "critical"] or findings
    return {
        "executive_summary": (
            f"Automated assessment shows {score}% audit readiness across the evaluated SOC 2 / ISO 27001 control tests. "
            + (f"{len(findings)} issue(s) need remediation before an audit; the most urgent is: {worst[0]['title'].lower()}."
               if findings else "No control failures were detected in the scanned configuration.")
        ),
        "top_risks": [f"{f['title']} ({', '.join(f['soc2'])})" for f in worst[:3]],
        "findings": [
            {"id": f["id"], "risk_explanation": CONTROLS[f["rule"]]["why"],
             "remediation": CONTROLS[f["rule"]]["fix"],
             "auditor_note": "Provide the fixed configuration and the passing scan output as evidence."}
            for f in findings
        ],
        "_source": "offline-catalog",
    }


def enrich(findings: list[dict], score: int, context: str = "full scan", use_ai: bool = True) -> dict:
    payload = [{k: f[k] for k in ("id", "rule", "title", "severity", "file", "line", "snippet", "detail", "soc2", "iso27001")}
               for f in findings]
    if not findings:
        return _fallback(findings, score, context)

    key = hashlib.sha256(json.dumps([MODEL, context, score, payload], sort_keys=True).encode()).hexdigest()[:16]
    cache = CACHE_DIR / f"{key}.json"
    if cache.exists():
        data = json.loads(cache.read_text(encoding="utf-8"))
        data["_source"] = f"cache ({MODEL})"
        return data

    if not use_ai or not (os.getenv("ANTHROPIC_API_KEY") or os.getenv("ANTHROPIC_AUTH_TOKEN")):
        return _fallback(findings, score, context)

    try:
        import anthropic

        client = anthropic.Anthropic(timeout=90, max_retries=1)
        prompt = (f"Context: {context}. Readiness score: {score}%.\nFindings JSON:\n"
                  + json.dumps(payload, indent=1))
        response = client.messages.create(
            model=MODEL,
            max_tokens=16000,
            system=SYSTEM,
            messages=[{"role": "user", "content": prompt}],
            output_config={"effort": "low", "format": {"type": "json_schema", "schema": SCHEMA}},
        )
        if response.stop_reason == "refusal":
            return _fallback(findings, score, context)
        text = next(b.text for b in response.content if b.type == "text")
        data = json.loads(text)
        CACHE_DIR.mkdir(exist_ok=True)
        cache.write_text(json.dumps(data, indent=2), encoding="utf-8")
        data["_source"] = MODEL
        return data
    except Exception as e:  # never let the AI layer break a compliance gate
        data = _fallback(findings, score, context)
        data["_source"] = f"offline-catalog (AI error: {type(e).__name__})"
        return data
