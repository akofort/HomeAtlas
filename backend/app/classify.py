"""LLM-assisted identification of discovered devices.

Discovery already produces a rule-based guess (see `discovery._guess`); this refines it using the
evidence a fingerprint table can't reason about -- an unfamiliar mDNS service name, a vendor
string plus an unusual port combination, a web page title in a foreign language.

Deliberately additive, never destructive:

* It runs only over devices the rules were unsure about, so a confidently-identified FRITZ!Box
  doesn't cost tokens.
* A low-confidence answer is discarded rather than written -- the rule-based guess is a better
  default than a shrug.
* Failure of the whole step is non-fatal: the scan completes with rule-based results and a warning.
"""
from __future__ import annotations

import json
import re

from . import llm_providers, prompts

# Small enough that one bad batch loses little work, large enough to amortize the prompt.
_BATCH_SIZE = 10

_VALID_KINDS = {
    "router", "network", "server", "nas", "container", "vm", "pc", "mobile", "printer", "camera",
    "smarthome", "climate", "heating", "energy", "media", "iot", "other",
}
_VALID_IMPORTANCE = {"critical", "normal", "low"}


def needs_classification(finding: dict) -> bool:
    """Only devices the rules couldn't place, and only if there is *something* to reason about.
    A silent host with no ports, no name and no vendor gives the model nothing but its IP -- asking
    anyway would invite a confident invention."""
    if finding.get("kind") not in ("other", ""):
        return False
    evidence = finding.get("extra") or {}
    return bool(
        finding.get("openPorts") or finding.get("vendor") or finding.get("hostname")
        or evidence.get("mdns") or evidence.get("ssdp") or evidence.get("httpBanner")
    )


def _evidence_for(finding: dict) -> dict:
    extra = finding.get("extra") or {}
    banner = extra.get("httpBanner") or {}
    return {
        "ip": finding.get("ip", ""),
        "hostname": finding.get("hostname", ""),
        "macVendor": finding.get("vendor", ""),
        "openPorts": [
            f"{s['port']} ({s['service']})" for s in (finding.get("services") or [])
        ][:20],
        "mdnsServices": [
            {"type": e.get("type", ""), "name": e.get("name", "")} for e in (extra.get("mdns") or [])
        ][:8],
        "upnp": [
            e.get("description") for e in (extra.get("ssdp") or []) if e.get("description")
        ][:4],
        "upnpServer": next((e.get("server", "") for e in (extra.get("ssdp") or []) if e.get("server")), ""),
        "webPageTitle": banner.get("title", ""),
        "webServerHeader": banner.get("server", ""),
    }


def _extract_json_array(text: str) -> list:
    """Models wrap JSON in prose or ```json fences often enough that a bare `json.loads` fails on
    otherwise perfect answers. Cut to the outermost array before parsing."""
    text = re.sub(r"^\s*```(?:json)?|```\s*$", "", text.strip(), flags=re.MULTILINE).strip()
    start, end = text.find("["), text.rfind("]")
    if start == -1 or end <= start:
        raise ValueError("Antwort enthielt kein JSON-Array.")
    value = json.loads(text[start:end + 1])
    if not isinstance(value, list):
        raise ValueError("Antwort war kein JSON-Array.")
    return value


async def classify(findings: list[dict], settings: dict, log=None) -> tuple[dict[str, dict], list[str]]:
    """Returns (by_ip, warnings). `by_ip` holds only entries worth applying."""
    warnings: list[str] = []
    candidates = [f for f in findings if needs_classification(f)]
    if not candidates:
        return {}, warnings

    by_ip: dict[str, dict] = {}
    for offset in range(0, len(candidates), _BATCH_SIZE):
        batch = candidates[offset:offset + _BATCH_SIZE]
        payload = json.dumps([_evidence_for(f) for f in batch], ensure_ascii=False, indent=1)
        try:
            result = await llm_providers.chat(
                settings.get("llmProvider", ""), settings, prompts.CLASSIFY_SYSTEM,
                [{"role": "user", "content": f"Ordne diese {len(batch)} Geräte ein:\n\n{payload}"}],
                purpose="CHAT",
            )
            entries = _extract_json_array(result.text)
        except (llm_providers.ProviderError, ValueError, json.JSONDecodeError) as exc:
            warnings.append(f"KI-Einordnung für {len(batch)} Geräte fehlgeschlagen: {exc}")
            if log:
                log(f"KI-Einordnung fehlgeschlagen: {exc}")
            continue

        known_ips = {f["ip"] for f in batch}
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            ip = str(entry.get("ip", "")).strip()
            # Guard against the model answering about a device that wasn't in this batch.
            if ip not in known_ips or entry.get("confidence") == "low":
                continue
            kind = entry.get("kind") if entry.get("kind") in _VALID_KINDS else "other"
            importance = entry.get("importance") if entry.get("importance") in _VALID_IMPORTANCE else "normal"
            by_ip[ip] = {
                "kind": kind,
                "name": str(entry.get("name") or "").strip()[:80],
                "vendor": str(entry.get("vendor") or "").strip()[:80],
                "model": str(entry.get("model") or "").strip()[:100],
                "purpose": str(entry.get("purpose") or "").strip()[:200],
                "descriptionMd": str(entry.get("description") or "").strip()[:800],
                "importance": importance,
                "confidence": entry.get("confidence", "medium"),
            }
        if log:
            log(f"KI-Einordnung: {len(batch)} Geräte geprüft")
    return by_ip, warnings


def apply(finding: dict, classification: dict) -> dict:
    """Merges one classification into a finding. Empty strings from the model never overwrite a
    value the rules already found -- a blank answer is an absence of information, not a correction."""
    merged = dict(finding)
    for field in ("kind", "name", "vendor", "model", "purpose", "descriptionMd", "importance"):
        value = classification.get(field)
        if value:
            merged[field] = value
    merged["discoverySource"] = f"{finding.get('discoverySource', '')}+ki".strip("+")
    merged["extra"] = {**(finding.get("extra") or {}),
                       "aiConfidence": classification.get("confidence", "medium")}
    return merged
