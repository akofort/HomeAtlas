"""The assistant's tool surface and the agent loop that drives it.

Two rules shape what is exposed here:

* **Read-only, plus bounded live measurements.** The model can look things up and run the
  diagnostics in `diagnostics.py`; it cannot edit the inventory, rewrite documentation, or change
  a device. Anything that modifies state stays behind the UI, where a human clicks it.
* **Stored secrets never reach the model.** `list_accounts` returns labels, usernames and notes so
  the assistant can say *where* a login is filed, and strips the password. That holds even though
  the model is "trusted" -- credentials in a prompt end up in the provider's logs, in the chat
  history, and in any future context window.
"""
from __future__ import annotations

import json

from . import crypto, db, diagnostics, docker_probe, llm_providers, prompts
from datetime import datetime, timezone

# A tool result is fed straight back into the context window; an unbounded one (a /24 inventory, a
# long traceroute) would crowd out the conversation. Truncation is announced in the payload so the
# model asks a narrower question instead of assuming it saw everything.
_MAX_RESULT_CHARS = 6000
_MAX_ITERATIONS = 8


TOOL_DEFINITIONS: list[dict] = [
    {
        "name": "list_systems",
        "description": ("Listet die dokumentierten Geräte des Haushalts. Nutze das, um einen umgangssprachlichen "
                        "Namen wie 'der Drucker' oder 'die Heizung' in ein konkretes Gerät mit IP-Adresse "
                        "aufzulösen, bevor du misst."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "kind": {"type": "string", "description": "Optionaler Filter auf eine Kategorie, z. B. printer, "
                                                          "router, server, nas, smarthome, heating, camera."},
                "query": {"type": "string", "description": "Optionaler Suchbegriff für Name, Hostname, IP, "
                                                           "Hersteller oder Modell."},
                "onlyOnline": {"type": "boolean", "description": "Nur Geräte, die beim letzten Scan erreichbar waren."},
            },
        },
    },
    {
        "name": "get_system",
        "description": "Liefert alle Details zu einem Gerät: Ports, Dienste, Beschreibung, Standort, Zweck.",
        "inputSchema": {
            "type": "object",
            "properties": {"idOrName": {"type": "string", "description": "Geräte-ID, Name oder IP-Adresse."}},
            "required": ["idOrName"],
        },
    },
    {
        "name": "network_overview",
        "description": ("Überblick über das Netzwerk: Adressbereiche, Router/Gateway, DNS-Server und eine "
                        "Zusammenfassung des letzten Scans. Guter erster Aufruf bei unklaren Problemen."),
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "list_documentation",
        "description": "Listet die Kapitel der Heimnetz-Dokumentation mit Titel und Kurzbeschreibung.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "get_documentation",
        "description": "Liefert den vollständigen Text eines Dokumentationskapitels.",
        "inputSchema": {
            "type": "object",
            "properties": {"slug": {"type": "string", "description": "Kürzel des Kapitels aus list_documentation."}},
            "required": ["slug"],
        },
    },
    {
        "name": "list_accounts",
        "description": ("Listet hinterlegte Zugänge und Konten OHNE Passwörter -- nur Bezeichnung, Benutzername, "
                        "Adresse und Notiz. Damit kannst du sagen, wo ein Zugang gespeichert ist; das Passwort "
                        "selbst liest die Person in der App nach."),
        "inputSchema": {
            "type": "object",
            "properties": {"systemId": {"type": "string", "description": "Optional: nur Zugänge zu diesem Gerät."}},
        },
    },
    {
        "name": "list_containers",
        "description": "Listet die Docker-Container auf dem Server: Image, Status, veröffentlichte Ports, Volumes.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "internet_check",
        "description": ("Prüft die Internetverbindung in drei Schichten (Erreichbarkeit, Namensauflösung, Webseiten) "
                        "und sagt, auf welcher Ebene es klemmt. Erster Griff bei 'Internet geht nicht'."),
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "ping_host",
        "description": "Prüft, ob ein Gerät im Netzwerk antwortet, und wie stabil die Verbindung ist.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "IP-Adresse oder Hostname."},
                "count": {"type": "integer", "description": "Anzahl Versuche, 1 bis 10. Standard 3."},
            },
            "required": ["host"],
        },
    },
    {
        "name": "check_port",
        "description": ("Prüft, ob ein bestimmter Dienst auf einem Gerät erreichbar ist, z. B. 80/443 für eine "
                        "Weboberfläche, 445 für Dateifreigaben, 9100 für Drucker."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "IP-Adresse oder Hostname."},
                "port": {"type": "integer", "description": "Portnummer 1-65535."},
            },
            "required": ["host", "port"],
        },
    },
    {
        "name": "dns_lookup",
        "description": "Prüft, ob ein Name in eine IP-Adresse übersetzt wird (Namensauflösung/DNS).",
        "inputSchema": {
            "type": "object",
            "properties": {"name": {"type": "string", "description": "Zu prüfender Name, z. B. www.google.com."}},
            "required": ["name"],
        },
    },
    {
        "name": "reverse_dns",
        "description": "Ermittelt den Gerätenamen zu einer IP-Adresse.",
        "inputSchema": {
            "type": "object",
            "properties": {"ip": {"type": "string", "description": "IP-Adresse."}},
            "required": ["ip"],
        },
    },
    {
        "name": "http_check",
        "description": "Ruft eine Weboberfläche auf und meldet Statuscode, Titel und Antwortzeit.",
        "inputSchema": {
            "type": "object",
            "properties": {"url": {"type": "string", "description": "Vollständige Adresse mit http:// oder https://."}},
            "required": ["url"],
        },
    },
    {
        "name": "traceroute",
        "description": ("Zeigt den Weg zu einem Ziel über die Zwischenstationen. Nützlich, um zu unterscheiden, ob "
                        "ein Problem im Heimnetz oder beim Internetanbieter liegt."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "IP-Adresse oder Hostname."},
                "maxHops": {"type": "integer", "description": "Maximale Zwischenstationen, 1 bis 30. Standard 15."},
            },
            "required": ["host"],
        },
    },
]


# ---------------------------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------------------------

def _slim_system(system: dict) -> dict:
    """Inventory rows carry raw discovery evidence (full mDNS/SSDP payloads) that would flood the
    context window without helping. Keep the human-meaningful fields."""
    return {
        "id": system["id"], "name": system["name"], "kind": system["kind"], "ip": system["ip"],
        "hostname": system["hostname"], "vendor": system["vendor"], "model": system["model"],
        "location": system["location"], "purpose": system["purpose"], "status": system["status"],
        "importance": system["importance"], "url": system["url"], "lastSeen": system["lastSeen"],
    }


def _find_system(id_or_name: str) -> dict | None:
    needle = (id_or_name or "").strip().lower()
    if not needle:
        return None
    direct = db.get_system(id_or_name)
    if direct:
        return direct
    systems = db.list_systems()
    for system in systems:
        if system["ip"].lower() == needle or system["name"].lower() == needle:
            return system
    for system in systems:
        haystack = " ".join([system["name"], system["hostname"], system["ip"], system["vendor"], system["model"]]).lower()
        if needle in haystack:
            return system
    return None


async def dispatch(name: str, arguments: dict) -> str:
    arguments = arguments if isinstance(arguments, dict) else {}
    try:
        result = await _dispatch(name, arguments)
    except diagnostics.DiagnosticError as exc:
        result = {"error": str(exc)}
    except Exception as exc:  # noqa: BLE001 -- a tool failure must reach the model as a result,
        # not crash the turn; the model can then explain the failure or try something else.
        result = {"error": f"Das Werkzeug '{name}' ist fehlgeschlagen: {exc}"}

    text = json.dumps(result, ensure_ascii=False, default=str)
    if len(text) > _MAX_RESULT_CHARS:
        text = text[:_MAX_RESULT_CHARS] + (
            '... ["Ergebnis gekürzt -- bitte gezielter nachfragen, z. B. mit einem Filter."]'
        )
    return text


async def _dispatch(name: str, args: dict) -> object:
    if name == "list_systems":
        systems = db.list_systems(args.get("kind") or None)
        query = (args.get("query") or "").strip().lower()
        if query:
            systems = [
                s for s in systems
                if query in " ".join([s["name"], s["hostname"], s["ip"], s["vendor"], s["model"],
                                      s["location"], s["purpose"]]).lower()
            ]
        if args.get("onlyOnline"):
            systems = [s for s in systems if s["status"] == "online"]
        return {"count": len(systems), "systems": [_slim_system(s) for s in systems]}

    if name == "get_system":
        system = _find_system(args.get("idOrName", ""))
        if system is None:
            return {"error": f"Kein Gerät gefunden, das zu '{args.get('idOrName', '')}' passt."}
        return {
            **_slim_system(system),
            "descriptionMd": system["descriptionMd"], "notes": system["notes"],
            "openPorts": system["openPorts"] or [], "services": system["services"] or [],
            "discoverySource": system["discoverySource"], "firstSeen": system["firstSeen"],
            "docker": (system.get("extra") or {}).get("docker"),
            "accountCount": len(db.list_accounts(system["id"])),
        }

    if name == "network_overview":
        settings = db.get_settings()
        scan = db.latest_scan()
        systems = db.list_systems()
        return {
            "homeName": settings.get("homeName"),
            "configuredSubnets": settings.get("scanSubnets") or "automatisch erkannt",
            "systemCount": len(systems),
            "onlineCount": sum(1 for s in systems if s["status"] == "online"),
            "byKind": {k: sum(1 for s in systems if s["kind"] == k) for k in sorted({s["kind"] for s in systems})},
            "lastScan": None if scan is None else {
                "startedAt": scan["startedAt"], "status": scan["status"],
                "subnets": scan["subnets"], "summary": scan["summary"],
            },
        }

    if name == "list_documentation":
        return {"pages": [
            {"slug": p["slug"], "title": p["title"], "topic": p["topic"], "intro": p["intro"]}
            for p in db.list_doc_pages()
        ]}

    if name == "get_documentation":
        page = db.get_doc_page(args.get("slug", ""))
        if page is None:
            return {"error": f"Kein Kapitel mit dem Kürzel '{args.get('slug', '')}'."}
        return {"slug": page["slug"], "title": page["title"], "bodyMd": page["bodyMd"]}

    if name == "list_accounts":
        accounts = db.list_accounts(args.get("systemId") or None)
        return {"count": len(accounts), "note": "Passwörter werden hier bewusst nicht ausgegeben.",
                "accounts": [
                    {"id": a["id"], "label": a["label"], "category": a["category"], "username": a["username"],
                     "url": a["url"], "notes": a["notes"], "systemId": a["systemId"],
                     "hasSecret": bool(a["secretEnc"])}
                    for a in accounts
                ]}

    if name == "list_containers":
        systems = db.list_systems("container")
        return {"count": len(systems), "containers": [
            {"name": s["name"], "image": s["model"], "status": s["status"], "ports": s["openPorts"] or [],
             **{k: v for k, v in ((s.get("extra") or {}).get("docker") or {}).items()
                if k in ("state", "status", "composeProject", "portMappings", "volumes", "networks")}}
            for s in systems
        ]}

    if name == "internet_check":
        return await diagnostics.internet_check()
    if name == "ping_host":
        return await diagnostics.ping(args.get("host", ""), args.get("count", 3))
    if name == "check_port":
        return await diagnostics.check_port(args.get("host", ""), args.get("port", 0))
    if name == "dns_lookup":
        return await diagnostics.dns_lookup(args.get("name", ""))
    if name == "reverse_dns":
        return await diagnostics.reverse_dns(args.get("ip", ""))
    if name == "http_check":
        return await diagnostics.http_check(args.get("url", ""))
    if name == "traceroute":
        return await diagnostics.traceroute(args.get("host", ""), args.get("maxHops", 15))

    return {"error": f"Unbekanntes Werkzeug '{name}'."}


# ---------------------------------------------------------------------------------------------
# Agent loop
# ---------------------------------------------------------------------------------------------

def _state_block(settings: dict) -> str:
    systems = db.list_systems()
    scan = db.latest_scan()
    return prompts.CHAT_STATE_TEMPLATE.format(
        timestamp=datetime.now(timezone.utc).strftime("%d.%m.%Y %H:%M UTC"),
        system_count=len(systems),
        online_count=sum(1 for s in systems if s["status"] == "online"),
        subnets=", ".join(settings.get("scanSubnets") or []) or "automatisch erkannt",
        gateway=next((s["ip"] for s in systems if (s.get("extra") or {}).get("isGateway")), "nicht ermittelt"),
        last_scan=f"{scan['startedAt']} ({scan['status']})" if scan else "noch keiner",
    )


def build_system_prompt(settings: dict) -> str:
    override = (settings.get("systemPromptOverride") or "").strip()
    base = override or prompts.CHAT_SYSTEM.format(home_name=settings.get("homeName") or "diesem Haushalt")
    return base + _state_block(settings)


def history_for_llm(chat_id: str) -> list[dict]:
    messages: list[dict] = []
    for m in db.list_chat_messages(chat_id):
        if m["role"] == "assistant" and m["toolCalls"]:
            messages.append({"role": "assistant", "content": m["content"], "tool_calls": m["toolCalls"],
                             "providerRaw": m["providerRaw"] or {}})
        elif m["role"] == "tool":
            messages.append({"role": "tool", "tool_call_id": m["toolCallId"] or "",
                             "name": m["name"] or "", "content": m["content"]})
        elif m["content"]:
            messages.append({"role": m["role"], "content": m["content"]})
    return messages


async def run_chat_turn(chat_id: str, user_text: str, settings: dict) -> dict:
    """Persists the user turn, then runs the model/tool loop until it produces a plain answer.
    Every intermediate step is persisted as it happens, so a crash or timeout leaves a readable
    transcript rather than a half-turn that can't be replayed."""
    db.add_chat_message(chat_id, "user", user_text)
    provider = settings.get("llmProvider", "")
    system_prompt = build_system_prompt(settings)
    used_tools: list[str] = []
    prompt_tokens = completion_tokens = 0

    for _ in range(_MAX_ITERATIONS):
        result = await llm_providers.chat(
            provider, settings, system_prompt, history_for_llm(chat_id),
            purpose="CHAT", tools=TOOL_DEFINITIONS,
        )
        prompt_tokens += result.prompt_tokens or 0
        completion_tokens += result.completion_tokens or 0

        if not result.tool_calls:
            message = db.add_chat_message(chat_id, "assistant", result.text)
            return {"message": message, "model": result.model, "toolsUsed": used_tools,
                    "usage": {"promptTokens": prompt_tokens, "completionTokens": completion_tokens}}

        db.add_chat_message(chat_id, "assistant", result.text, tool_calls=result.tool_calls,
                            provider_raw=result.provider_raw or None)
        for call in result.tool_calls:
            used_tools.append(call["name"])
            output = await dispatch(call["name"], call.get("arguments") or {})
            db.add_chat_message(chat_id, "tool", output, tool_call_id=call["id"], name=call["name"])

    # Out of iterations: say so in the transcript rather than silently returning the last tool
    # output, which would look like the assistant ignored the question.
    message = db.add_chat_message(chat_id, "assistant", (
        "Ich habe mehrere Prüfungen hintereinander durchgeführt und komme so nicht weiter, ohne den "
        "Rahmen zu sprengen. Magst du die Frage etwas eingrenzen -- zum Beispiel auf ein bestimmtes "
        "Gerät oder einen bestimmten Dienst?"
    ))
    return {"message": message, "model": "", "toolsUsed": used_tools,
            "usage": {"promptTokens": prompt_tokens, "completionTokens": completion_tokens}}


def decrypt_account(account: dict) -> dict:
    """UI-only path -- deliberately not reachable from any tool."""
    return {**account, "secret": crypto.decrypt(account.get("secretEnc") or "")}


def docker_available() -> bool:
    return docker_probe.socket_available()
