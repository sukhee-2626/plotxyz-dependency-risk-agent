"""Original deterministic implementation for Dependency Risk (plotxyz-dependency-risk-agent)."""
from __future__ import annotations

import ast
import csv
import io
import json
import math
import os
import re
import statistics
import time
from collections import Counter, defaultdict, deque


class LogicError(ValueError):
    """Raised when supplied input cannot be processed."""


def _text(payload, key, min_len=1, max_len=20000):
    value = payload.get(key)
    if not isinstance(value, str):
        raise LogicError(f"'{key}' must be a string")
    value = value.strip()
    if len(value) < min_len:
        raise LogicError(f"'{key}' is required")
    if len(value) > max_len:
        raise LogicError(f"'{key}' exceeds {max_len} characters")
    return value


def _num(payload, key, default=None, lo=None, hi=None):
    value = payload.get(key, default)
    if value is None or value == "":
        if default is None:
            raise LogicError(f"'{key}' is required")
        return default
    if isinstance(value, bool):
        raise LogicError(f"'{key}' must be numeric")
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise LogicError(f"'{key}' must be numeric")
    if lo is not None and number < lo:
        raise LogicError(f"'{key}' must be at least {lo}")
    if hi is not None and number > hi:
        raise LogicError(f"'{key}' must be at most {hi}")
    return number


def _json(payload, key, expected=None, max_len=200000):
    raw = payload.get(key)
    if isinstance(raw, (dict, list)):
        data = raw
    elif isinstance(raw, str):
        if len(raw) > max_len:
            raise LogicError(f"'{key}' exceeds {max_len} characters")
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise LogicError(f"'{key}' is not valid JSON: {exc.msg} at line {exc.lineno}")
    else:
        raise LogicError(f"'{key}' must be JSON")
    if expected is not None and not isinstance(data, expected):
        name = expected.__name__ if hasattr(expected, "__name__") else str(expected)
        raise LogicError(f"'{key}' must be a JSON {name}")
    return data


def _csv(payload, key, max_rows=5000):
    text = _text(payload, key, max_len=2000000)
    try:
        reader = csv.DictReader(io.StringIO(text))
        if not reader.fieldnames:
            raise LogicError(f"'{key}' must include a header row")
        columns = [str(c).strip() for c in reader.fieldnames if c and str(c).strip()]
        if not columns:
            raise LogicError(f"'{key}' must include named columns")
        rows = []
        for index, raw in enumerate(reader):
            if index >= max_rows:
                raise LogicError(f"'{key}' exceeds {max_rows} rows")
            rows.append({col: (raw.get(col) or "").strip() for col in columns})
    except csv.Error as exc:
        raise LogicError(f"'{key}' is not valid CSV: {exc}")
    if not rows:
        raise LogicError(f"'{key}' must include at least one data row")
    return columns, rows


STOPWORDS = {'will', 'they', 'was', 'your', 'than', 'that', 'on', 'be', 'then', 'do', 'our', 'with', 'he', 'is', 'about', 'had', 'were', 'as', 'may', 'we', 'their', 'are', 'did', 'at', 'she', 'a', 'by', 'the', 'if', 'might', 'it', 'into', 'have', 'from', 'should', 'not', 'over', 'can', 'for', 'and', 'an', 'you', 'does', 'to', 'this', 'could', 'would', 'under', 'of', 'no', 'its', 'in', 'i', 'or', 'has'}


def _tokens(text):
    return [w for w in re.findall(r"[a-z0-9][a-z0-9_+-]{1,}", text.lower()) if w not in STOPWORDS]


def _sentences(text):
    parts = re.split(r"(?<=[.!?])\s+|\n+", text)
    return [p.strip(" -•\t") for p in parts if len(p.strip()) > 2]


def provider_status():
    """Report which optional model providers are configured (never exposes secrets)."""
    ollama = bool(os.getenv("OLLAMA_BASE_URL"))
    openai = bool(os.getenv("OPENAI_BASE_URL") and os.getenv("OPENAI_MODEL"))
    return {"ollama_compatible": ollama, "openai_compatible": openai}


def _llm(messages, temperature=0.2):
    """Call an explicitly configured OpenAI-compatible endpoint; return None when unavailable."""
    base = os.getenv("OPENAI_BASE_URL", "").rstrip("/")
    model = os.getenv("OPENAI_MODEL", "")
    if not base or not model:
        ollama = os.getenv("OLLAMA_BASE_URL", "").rstrip("/")
        if not ollama:
            return None
        base = f"{ollama}/v1"
        model = os.getenv("OLLAMA_MODEL", "")
    if not model:
        return None
    try:
        import httpx

        headers = {"Content-Type": "application/json"}
        key = os.getenv("OPENAI_API_KEY")
        if key:
            headers["Authorization"] = f"Bearer {key}"
        with httpx.Client(timeout=20) as client:
            response = client.post(
                f"{base}/chat/completions",
                headers=headers,
                json={"model": model, "messages": messages, "temperature": temperature},
            )
            response.raise_for_status()
            return str(response.json()["choices"][0]["message"]["content"]).strip()
    except Exception:
        return None


def _result(summary, result, warnings=None):
    return {"summary": summary, "result": result, "warnings": warnings or []}


def agent_dependency_risk(payload):
    manifest = _text(payload, "manifest", max_len=120000)
    ecosystem = str(payload.get("ecosystem", "requirements")).lower()
    check_osv = bool(payload.get("check_osv", False))
    dependencies = []
    if ecosystem == "package":
        try:
            data = json.loads(manifest)
        except json.JSONDecodeError as exc:
            raise LogicError(f"manifest is not valid package.json: {exc.msg}")
        for section in ("dependencies", "devDependencies"):
            for name, constraint in (data.get(section) or {}).items():
                dependencies.append((name, str(constraint), section))
    else:
        for line in manifest.splitlines():
            line = line.split("#", 1)[0].strip()
            if not line or line.startswith(("-", "git+", "http")):
                continue
            match = re.match(r"^([A-Za-z0-9_.-]+)\s*(.*)$", line)
            if match:
                dependencies.append((match.group(1), match.group(2).strip(), "runtime"))
    if not dependencies:
        raise LogicError("no dependencies were found in the manifest")
    findings, rows = [], []
    deprecated = {"request", "left-pad", "tslint", "node-sass"}
    advisories = []
    for name, constraint, section in dependencies[:200]:
        pinned = constraint.startswith("==") if ecosystem != "package" else bool(re.fullmatch(r"\d+\.\d+\.\d+", constraint))
        risky = []
        if not pinned:
            risky.append("not exactly pinned")
        if constraint.strip() in {"*", "latest", ""} or constraint.startswith(("^", "~", ">", "<")):
            risky.append("range or wildcard")
        if constraint.startswith(("git+", "http://", "https://", "file:")):
            risky.append("non-registry source")
        if name.lower() in deprecated:
            risky.append("commonly deprecated")
        rows.append([name, constraint, section, "pinned" if pinned else "floating", ", ".join(risky) or "ok"])
        if "non-registry source" in risky:
            findings.append({"title": "Unverified dependency source", "severity": "high", "detail": f"{name} is sourced outside the registry; verify provenance and integrity."})
        elif "not exactly pinned" in risky:
            findings.append({"title": "Floating version", "severity": "low", "detail": f"{name} ({constraint}) can change between installs."})
    if check_osv:
        try:
            import httpx

            for name, constraint, _ in dependencies[:30]:
                version = constraint[2:] if constraint.startswith("==") else (constraint if re.fullmatch(r"\d+\.\d+\.\d+", constraint) else None)
                if not version:
                    continue
                response = httpx.post(
                    "https://api.osv.dev/v1/query",
                    json={"package": {"name": name, "ecosystem": "PyPI" if ecosystem != "package" else "npm"}, "version": version},
                    timeout=8,
                )
                if response.status_code == 200:
                    for vuln in response.json().get("vulns", [])[:3]:
                        advisories.append([name, version, vuln.get("id", "unknown"), (vuln.get("summary") or "")[:120]])
        except Exception as exc:
            findings.append({"title": "Advisory lookup unavailable", "severity": "info", "detail": f"OSV lookup failed ({type(exc).__name__}); no advisory results are claimed."})
    for advisory in advisories:
        findings.append({"title": "OSV advisory", "severity": "high", "detail": f"{advisory[0]} {advisory[1]}: {advisory[2]} — {advisory[3]}"})
    score = max(0, 100 - len([f for f in findings if f["severity"] == "high"]) * 15 - len([f for f in findings if f["severity"] == "low"]) * 3)
    return _result(
        f"Reviewed {len(dependencies)} dependency entries; {len(advisories)} advisory record(s) returned.",
        {
            "metrics": {"dependencies": len(dependencies), "advisories": len(advisories), "score": score},
            "table": {"columns": ["Dependency", "Constraint", "Section", "Pinning", "Notes"], "rows": rows},
            "findings": findings,
        },
        ["Offline mode checks hygiene only. Enable check_osv for authoritative OSV advisory queries; no advisories are invented."],
    )


run = agent_dependency_risk
