"""Turns the inventory into topic-sorted Markdown that a non-technical household member can read.

Chapters are organised by *what something is for* ("Wärme, Klima und Energie") rather than by
protocol or address range, because that is how someone looks for it when the heating app stops
working.

Each page is assembled in two layers. The factual layer -- device tables, ports, accounts, the
emergency checklist -- is generated deterministically from the database and is always correct
without any LLM involved. The narrative intro on top is optional and LLM-written; if no API key is
configured, or the call fails, a hand-written fallback is used and the page is still complete.
That split is deliberate: documentation that silently degrades to nothing when a token expires
would be worse than useless.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import db, llm_providers, prompts

KIND_LABELS = {
    "router": "Router", "network": "Netzwerk-Gerät", "server": "Server", "nas": "Netzwerkspeicher",
    "container": "Container", "vm": "Virtuelle Maschine", "pc": "Computer", "mobile": "Mobilgerät",
    "printer": "Drucker", "camera": "Kamera", "smarthome": "Smart Home", "climate": "Klima",
    "heating": "Heizung", "energy": "Energie", "media": "Medien", "iot": "IoT-Gerät", "other": "Sonstiges",
}

STATUS_LABELS = {"online": "erreichbar", "offline": "nicht erreichbar", "unknown": "unbekannt"}
IMPORTANCE_LABELS = {"critical": "kritisch", "normal": "normal", "low": "gering"}


@dataclass(frozen=True)
class Topic:
    slug: str
    title: str
    kinds: tuple[str, ...]
    intro_hint: str
    fallback: str
    sort_order: int
    include_accounts: bool = False
    extra_sections: tuple[str, ...] = field(default=())


TOPICS: tuple[Topic, ...] = (
    Topic(
        "ueberblick", "Überblick: So hängt alles zusammen", (),
        "Ein Überblick über das gesamte Heimnetz: was es gibt, wie die Teile zusammenhängen und wo man anfängt zu suchen.",
        "Diese Seite fasst zusammen, woraus das Heimnetz besteht. Die Kapitel danach gehen ins Detail.",
        0,
    ),
    Topic(
        "internet-und-router", "Internet und Router", ("router",),
        "Der Router und die Verbindung ins Internet.",
        "Der Router ist die Schaltzentrale des Heimnetzes: Er verbindet alle Geräte im Haus miteinander "
        "und stellt die Verbindung ins Internet her. Fällt er aus, funktioniert nichts mehr -- weder "
        "Internet noch das Netz im Haus selbst.",
        1,
    ),
    Topic(
        "netzwerk", "Netzwerk: Switche, WLAN und Verkabelung", ("network",),
        "Switche, Access Points und WLAN-Verstärker, die das Netz im Haus verteilen.",
        "Diese Geräte verteilen das Netzwerk im Haus weiter: Switche verbinden Geräte per Kabel, "
        "Access Points und Repeater bringen das WLAN in entferntere Räume.",
        2,
    ),
    Topic(
        "server-und-speicher", "Server und Netzwerkspeicher", ("server", "nas"),
        "Dauerhaft laufende Rechner und Netzwerkspeicher.",
        "Hier laufen die Dienste, die immer verfügbar sein sollen, und hier liegen zentrale Daten. "
        "Diese Geräte laufen typischerweise rund um die Uhr.",
        3,
    ),
    Topic(
        "container-und-vms", "Container und virtuelle Maschinen", ("container", "vm"),
        "Die einzelnen Anwendungen, die auf dem Server in Containern laufen.",
        "Container sind voneinander abgeschottete kleine Anwendungspakete auf einem Server. Jeder "
        "enthält genau eine Anwendung mit allem, was sie zum Laufen braucht. Startet ein Container "
        "nicht mehr, ist meist nur diese eine Anwendung betroffen -- der Rest läuft weiter.",
        4,
    ),
    Topic(
        "computer-und-mobilgeraete", "Computer und Mobilgeräte", ("pc", "mobile"),
        "Arbeitsplatzrechner, Notebooks, Tablets und Telefone.",
        "Die persönlichen Geräte im Haushalt. Diese sind nicht immer eingeschaltet -- dass eines "
        "gerade nicht erreichbar ist, ist hier also normal. Telefone wechseln außerdem regelmäßig "
        "ihre Netzwerkkennung, sie können deshalb mehrfach auftauchen.",
        5,
    ),
    Topic(
        "smart-home", "Smart Home und Automation", ("smarthome", "iot"),
        "Die Smart-Home-Zentrale und die daran angebundenen Geräte.",
        "Smart-Home-Geräte werden meist über eine Zentrale gesteuert. Reagiert ein einzelnes Gerät "
        "nicht mehr, lohnt der erste Blick auf diese Zentrale -- oft ist nicht das Gerät das Problem, "
        "sondern die Verbindung dorthin.",
        6,
    ),
    Topic(
        "klima-heizung-energie", "Wärme, Klima und Energie", ("heating", "climate", "energy"),
        "Heizung, Klimatisierung, Photovoltaik und alles rund um Energie.",
        "Heizungs- und Energietechnik hängt oft am Netzwerk, um Daten zu liefern oder fernsteuerbar zu "
        "sein. Wichtig: Die Heizung selbst funktioniert in aller Regel weiter, auch wenn ihre "
        "Netzwerkverbindung gestört ist -- dann fehlt nur die Anzeige oder die Fernsteuerung.",
        7,
    ),
    Topic(
        "drucker-medien-kameras", "Drucker, Medien und Kameras", ("printer", "media", "camera"),
        "Drucker, Streaming-Geräte, Lautsprecher und Kameras.",
        "Geräte, die im Alltag sichtbar genutzt werden. Drucker und Streaming-Geräte melden sich meist "
        "selbst im Netzwerk an, damit andere Geräte sie automatisch finden.",
        8,
    ),
    Topic(
        "sonstige-geraete", "Weitere Geräte", ("other",),
        "Geräte, die sich noch nicht eindeutig zuordnen ließen.",
        "Diese Geräte antworten im Netzwerk, ließen sich aber noch nicht sicher einordnen. Wer weiß, "
        "worum es sich handelt, kann sie in der Geräteübersicht benennen -- danach bleibt die Angabe "
        "erhalten und wird bei künftigen Scans nicht überschrieben.",
        9,
    ),
    Topic(
        "zugaenge-und-konten", "Zugänge und Konten", (),
        "Wo welche Zugangsdaten hinterlegt sind.",
        "Hier ist vermerkt, für welche Geräte und Dienste Zugangsdaten in HomeAtlas hinterlegt sind. "
        "Die Passwörter selbst stehen bewusst nicht in dieser Dokumentation -- sie sind verschlüsselt "
        "gespeichert und nur in der Geräteansicht sichtbar.",
        10, include_accounts=True,
    ),
    Topic(
        "notfall", "Wenn etwas nicht funktioniert", (),
        "Eine Checkliste für den Störungsfall.",
        "", 11, extra_sections=("emergency",),
    ),
)


# What a device of this kind is *for*, in one sentence a non-technical reader understands. Used
# only when nothing better is stored, so a real description or an LLM-written purpose always wins.
_KIND_PURPOSE = {
    "router": "Verbindet das Haus mit dem Internet und verteilt das Netz an alle Geräte.",
    "network": "Verteilt das Netzwerk im Haus weiter — per Kabel oder als WLAN.",
    "server": "Ein dauerhaft laufender Rechner, auf dem Dienste für den Haushalt bereitstehen.",
    "nas": "Zentraler Netzwerkspeicher: hier liegen gemeinsam genutzte Dateien und Sicherungen.",
    "container": "Eine einzelne Anwendung, abgeschottet auf einem Server ausgeführt.",
    "vm": "Ein vollständiger virtueller Rechner, der auf einem größeren Server läuft.",
    "pc": "Ein persönlicher Rechner im Haushalt.",
    "mobile": "Ein Telefon oder Tablet im WLAN.",
    "printer": "Netzwerkdrucker, über den alle Geräte im Haus drucken können.",
    "camera": "Kamera, die ihr Bild über das Netzwerk bereitstellt.",
    "smarthome": "Teil der Smart-Home-Steuerung — schaltet, misst oder steuert etwas im Haus.",
    "climate": "Steuert oder misst Temperatur, Lüftung oder Luftqualität.",
    "heating": "Gehört zur Heizung oder Wärmepumpe.",
    "energy": "Gehört zur Energieversorgung — Photovoltaik, Ladestation oder Stromzähler.",
    "media": "Gibt Musik oder Video wieder oder streamt es ins Haus.",
    "iot": "Kleines vernetztes Gerät mit einer speziellen Aufgabe.",
    "other": "",
}


def describe_device(system: dict) -> str:
    """Best available "what is this for" sentence.

    Falls back through: hand-written description → purpose → what the kind implies, enriched by the
    most telling open service. Without the fallback most entries in "Die Geräte im Einzelnen" would
    show nothing at all, which is precisely the section someone reads to find out what a device is.
    """
    description = (system.get("descriptionMd") or "").strip()
    if description:
        return description
    purpose = (system.get("purpose") or "").strip()
    if purpose and not purpose.startswith("Gerät "):
        return purpose

    base = _KIND_PURPOSE.get(system.get("kind", ""), "")
    services = system.get("services") or []
    hint = ""
    if services:
        # Name the single most identifying service rather than listing ports.
        primary = next(
            (s for s in services if s["port"] in (8123, 32400, 8096, 9100, 631, 445, 5001, 8006, 1883, 554)),
            services[0],
        )
        hint = f" Erreichbar ist unter anderem {primary['service']} — {primary['explanation'][0].lower()}{primary['explanation'][1:]}."

    docker = (system.get("extra") or {}).get("docker") or {}
    if docker.get("image"):
        hint = f" Läuft als Container aus dem Image `{docker['image']}`." + hint

    if not base and not hint:
        return ""
    return (base + hint).strip()


def _fmt_date(value: str | None) -> str:
    if not value:
        return "-"
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").strftime("%d.%m.%Y %H:%M")
    except (ValueError, TypeError):
        return value


def _escape(text: str) -> str:
    """Markdown tables break on a raw pipe in a device name; devices really are named things like
    'Drucker | Büro'."""
    return (text or "").replace("|", "\\|").replace("\n", " ").strip()


def _device_table(systems: list[dict]) -> str:
    if not systems:
        return "_In dieser Kategorie ist bisher nichts dokumentiert._\n"
    lines = [
        "| Gerät | Adresse im Netz | Art | Zustand | Standort |",
        "| --- | --- | --- | --- | --- |",
    ]
    for s in systems:
        address = s["ip"] or "-"
        if s["hostname"]:
            address = f"{address} ({_escape(s['hostname'].split('.')[0])})"
        lines.append(
            f"| **{_escape(s['name'])}** | {_escape(address)} | {KIND_LABELS.get(s['kind'], s['kind'])} "
            f"| {STATUS_LABELS.get(s['status'], s['status'])} | {_escape(s['location']) or '-'} |"
        )
    return "\n".join(lines) + "\n"


def _device_details(systems: list[dict], by_id: dict[str, dict], children_by_parent: dict[str, list[dict]]) -> str:
    parts: list[str] = []
    for s in systems:
        parts.append(f"### {s['name']}\n")
        description = describe_device(s)
        if description:
            parts.append(f"{description}\n")

        facts = []
        if s["ip"]:
            facts.append(f"- **Adresse im Netzwerk:** {s['ip']}")
        if s["mac"]:
            facts.append(f"- **Geräte-Kennung (MAC):** `{s['mac']}`")
        if s["vendor"]:
            facts.append(f"- **Hersteller:** {_escape(s['vendor'])}")
        if s["model"]:
            facts.append(f"- **Modell:** {_escape(s['model'])}")
        if s["location"]:
            facts.append(f"- **Standort:** {_escape(s['location'])}")
        if s["importance"] != "normal":
            facts.append(f"- **Bedeutung:** {IMPORTANCE_LABELS.get(s['importance'], s['importance'])}")
        parent = by_id.get(s.get("parentId") or "")
        if parent:
            facts.append(f"- **Läuft auf:** {_escape(parent['name'])}")
        if s["url"]:
            facts.append(f"- **Weboberfläche:** [{s['url']}]({s['url']})")
        if s.get("docUrl"):
            facts.append(f"- **Hersteller-Dokumentation:** [{s['docUrl']}]({s['docUrl']})")
        if s.get("docLink"):
            facts.append(f"- **Eigene Dokumentation:** [{s['docLink']}]({s['docLink']})")
        facts.append(f"- **Zuletzt gesehen:** {_fmt_date(s['lastSeen'])}")
        parts.append("\n".join(facts) + "\n")

        probe = (s.get("extra") or {}).get("probe") or {}
        readings = [
            (fact["label"], fact["value"])
            for result in probe.values() if result.get("ok")
            for fact in (result.get("facts") or {}).values()
        ]
        if readings:
            parts.append("**Direkt vom Gerät ausgelesen**\n")
            for label, value in readings[:14]:
                # Multi-line command output (disks, services) belongs in a code block; a single
                # value reads better inline.
                if "\n" in value:
                    parts.append(f"- **{_escape(label)}:**\n\n  ```\n  " + value.replace("\n", "\n  ") + "\n  ```\n")
                else:
                    parts.append(f"- **{_escape(label)}:** {_escape(value)}")
            parts.append("")

        docker = (s.get("extra") or {}).get("docker") or {}
        if docker:
            docker_facts = [f"- **Image:** `{docker.get('image', '')}`"]
            if docker.get("composeProject"):
                docker_facts.append(f"- **Compose-Projekt:** `{docker['composeProject']}`")
            if docker.get("portMappings"):
                docker_facts.append(f"- **Port-Weiterleitungen:** `{', '.join(docker['portMappings'])}`")
            if docker.get("volumes"):
                docker_facts.append(f"- **Datenablagen (Volumes):** `{', '.join(docker['volumes'][:6])}`")
            parts.append("\n".join(docker_facts) + "\n")

        proxmox = (s.get("extra") or {}).get("proxmox") or {}
        if proxmox:
            proxmox_facts = [f"- **Proxmox-Node:** {_escape(str(proxmox.get('node', '')))}"]
            if proxmox.get("vmid"):
                proxmox_facts.append(f"- **VM-/Container-ID:** {proxmox['vmid']}")
            if proxmox.get("cpuCores"):
                proxmox_facts.append(f"- **CPU-Kerne:** {proxmox['cpuCores']}")
            if proxmox.get("memoryMb"):
                proxmox_facts.append(f"- **Arbeitsspeicher:** {proxmox['memoryMb']} MB")
            parts.append("\n".join(proxmox_facts) + "\n")

        children = sorted(children_by_parent.get(s["id"], []), key=lambda c: c["name"])
        if children:
            parts.append("**Läuft auf diesem Gerät**\n")
            child_rows = ["| Name | Art | Zustand | Funktion | Weboberfläche |", "| --- | --- | --- | --- | --- |"]
            for c in children:
                link = f"[öffnen]({c['url']})" if c.get("url") else "-"
                child_rows.append(
                    f"| **{_escape(c['name'])}** | {KIND_LABELS.get(c['kind'], c['kind'])} "
                    f"| {STATUS_LABELS.get(c['status'], c['status'])} "
                    f"| {_escape(describe_device(c))[:140] or '-'} | {link} |"
                )
            parts.append("\n".join(child_rows) + "\n")

        services = s.get("services") or []
        if services:
            parts.append("**Erreichbare Dienste**\n")
            parts.append("| Port | Dienst | Bedeutung |\n| --- | --- | --- |")
            parts.append("\n".join(
                f"| {svc['port']} | {_escape(svc['service'])} | {_escape(svc['explanation'])} |"
                for svc in services[:15]
            ) + "\n")

        if any("poe" in tag.lower() for tag in (s.get("tags") or [])):
            parts.append(
                "> ⚡ **Benötigt PoE:** Dieses Gerät bezieht seinen Strom über das Netzwerkkabel "
                "und funktioniert nur an einem PoE-fähigen Switch oder mit einem PoE-Injector.\n"
            )

        if s["notes"]:
            parts.append(f"> **Notiz:** {_escape(s['notes'])}\n")
    return "\n".join(parts)


def _accounts_section() -> str:
    accounts = db.list_accounts()
    if not accounts:
        return ("_Es sind bisher keine Zugänge hinterlegt._ Zugänge lassen sich in der Geräteansicht "
                "oder über die Ersteinrichtung ergänzen.\n")
    systems = {s["id"]: s["name"] for s in db.list_systems()}
    lines = [
        "| Zugang | Art | Benutzername | Gehört zu | Adresse | Passwort hinterlegt |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    categories = {"login": "Anmeldung", "apikey": "API-Schlüssel", "wifi": "WLAN",
                  "contract": "Vertrag/Kundenkonto", "other": "Sonstiges"}
    for a in accounts:
        url = f"[{_escape(a['url'])}]({a['url']})" if a["url"] else "-"
        lines.append(
            f"| **{_escape(a['label'])}** | {categories.get(a['category'], a['category'])} "
            f"| {_escape(a['username']) or '-'} | {_escape(systems.get(a['systemId'] or '', '-'))} "
            f"| {url} | {'ja' if a['secretEnc'] else 'nein'} |"
        )
    return "\n".join(lines) + (
        "\n\n> Die Passwörter selbst stehen absichtlich nicht in der Dokumentation. Sie sind "
        "verschlüsselt gespeichert und lassen sich in HomeAtlas beim jeweiligen Zugang anzeigen.\n"
    )


def _emergency_section(context: dict) -> str:
    router = context.get("router")
    router_line = (
        f"Der Router ist **{router['name']}** und ist im Netzwerk unter **{router['ip']}** erreichbar"
        + (f" -- Weboberfläche: [{router['url']}]({router['url']})" if router.get("url") else "")
        + "."
    ) if router else "Es ist noch kein Router dokumentiert -- ein Netzwerk-Scan trägt ihn automatisch ein."

    critical = context.get("critical") or []
    critical_lines = "\n".join(
        f"- **{_escape(s['name'])}** ({s['ip'] or 'keine Adresse hinterlegt'}) -- "
        f"{_escape(s['purpose'] or 'kein Zweck hinterlegt')}"
        for s in critical
    ) or "_Es ist bisher kein Gerät als kritisch markiert._"

    return f"""\
Diese Seite ist für den Fall gedacht, dass gerade etwas nicht funktioniert. Sie ist bewusst so
geschrieben, dass man ihr auch unter Zeitdruck folgen kann.

### Zuerst: Wie groß ist das Problem?

1. **Betrifft es nur ein Gerät?** Dann liegt es sehr wahrscheinlich an diesem Gerät. Aus- und
   wieder einschalten löst erstaunlich viel.
2. **Betrifft es alle Geräte, aber nur im Internet?** Also: das Heimnetz funktioniert (Drucker,
   Dateien, Smart Home gehen), nur Webseiten laden nicht. Dann liegt es am Internetzugang oder am
   Anbieter -- nicht an den Geräten im Haus.
3. **Geht gar nichts mehr?** Dann zuerst zum Router.

### Der Router

{router_line}

Am Router prüfen:
- Leuchten die Lampen wie sonst? Eine rote oder dunkle Internet-/DSL-Lampe heißt: die Leitung ins
  Haus ist gestört. Das kann man von innen nicht reparieren.
- Wenn unklar: Router 30 Sekunden vom Strom trennen, wieder anstecken und **zwei bis drei Minuten
  warten**. Er braucht diese Zeit, um die Internetverbindung neu aufzubauen.

### Diese Geräte sind besonders wichtig

Wenn eines davon ausfällt, merkt man das im ganzen Haus:

{critical_lines}

### Wenn es dabei bleibt

Der KI-Assistent in HomeAtlas kann live nachmessen: ob ein Gerät antwortet, ob die Namensauflösung
funktioniert, ob das Internet erreichbar ist. Beschreibe dort einfach in eigenen Worten, was nicht
geht -- er fragt gezielt nach und prüft selbst, statt dich raten zu lassen.
"""


def _overview_section(context: dict) -> str:
    counts = context.get("counts") or {}
    if not counts:
        return "_Noch keine Geräte dokumentiert. Starte einen Netzwerk-Scan, um zu beginnen._\n"
    lines = ["| Bereich | Anzahl Geräte |", "| --- | --- |"]
    lines += [f"| {KIND_LABELS.get(kind, kind)} | {count} |" for kind, count in sorted(
        counts.items(), key=lambda item: (-item[1], item[0])
    )]
    scan = context.get("last_scan")
    footer = (
        f"\nLetzter Netzwerk-Scan: **{_fmt_date(scan['startedAt'])}** "
        f"({', '.join(context.get('subnets') or []) or 'automatisch erkannter Bereich'}).\n"
        if scan else "\n_Es wurde noch kein Netzwerk-Scan durchgeführt._\n"
    )
    return "\n".join(lines) + "\n" + footer


async def _write_intro(topic: Topic, systems: list[dict], settings: dict) -> str:
    """LLM-written chapter intro. Returns the fallback on any failure -- a missing API key must not
    produce an empty page."""
    if not settings.get("scanUseLlm", True):
        return topic.fallback
    device_summary = "\n".join(
        f"- {s['name']} ({KIND_LABELS.get(s['kind'], s['kind'])})"
        + (f", {s['vendor']}" if s["vendor"] else "")
        + (f", Zweck: {s['purpose']}" if s["purpose"] else "")
        for s in systems[:25]
    ) or "(keine Geräte in dieser Kategorie)"
    try:
        result = await llm_providers.chat(
            settings.get("llmProvider", ""), settings, prompts.DOCS_SYSTEM,
            [{"role": "user", "content": (
                f"Kapitel: {topic.title}\nWorum es geht: {topic.intro_hint}\n\n"
                f"Diese Geräte sind in diesem Kapitel dokumentiert:\n{device_summary}\n\n"
                "Schreibe den einleitenden Text für dieses Kapitel."
            )}],
            purpose="ANALYSIS",
        )
        text = result.text.strip()
        return text or topic.fallback
    except Exception:  # noqa: BLE001 -- a chapter intro is never worth failing the whole run over
        return topic.fallback


def _systems_for(topic: Topic, all_systems: list[dict]) -> list[dict]:
    if not topic.kinds:
        return []
    return [s for s in all_systems if s["kind"] in topic.kinds]


async def generate(settings: dict, use_llm: bool = True, log=None) -> list[str]:
    """Regenerates every chapter. Returns the slugs written."""
    all_systems = db.list_systems()
    by_id = {s["id"]: s for s in all_systems}
    children_by_parent: dict[str, list[dict]] = {}
    for s in all_systems:
        parent_id = s.get("parentId")
        if parent_id:
            children_by_parent.setdefault(parent_id, []).append(s)
    context = {
        "counts": {k: sum(1 for s in all_systems if s["kind"] == k) for k in {s["kind"] for s in all_systems}},
        "router": next((s for s in all_systems if s["kind"] == "router"), None),
        "critical": [s for s in all_systems if s["importance"] == "critical"],
        "last_scan": db.latest_scan(),
        "subnets": settings.get("scanSubnets") or [],
    }

    written: list[str] = []
    for topic in TOPICS:
        systems = _systems_for(topic, all_systems)
        sections: list[str] = []

        if "emergency" in topic.extra_sections:
            body = _emergency_section(context)
            intro = topic.intro_hint
        else:
            intro_text = (
                await _write_intro(topic, systems, settings)
                if use_llm and topic.kinds and systems else topic.fallback
            )
            sections.append(intro_text)
            if topic.slug == "ueberblick":
                sections.append("\n## Was es im Heimnetz gibt\n")
                sections.append(_overview_section(context))
            if topic.include_accounts:
                sections.append("\n## Hinterlegte Zugänge\n")
                sections.append(_accounts_section())
            if topic.kinds:
                sections.append("\n## Geräte auf einen Blick\n")
                sections.append(_device_table(systems))
                if systems:
                    sections.append("\n## Die Geräte im Einzelnen\n")
                    sections.append(_device_details(systems, by_id, children_by_parent))
            body = "\n".join(sections)
            intro = topic.intro_hint

        db.upsert_doc_page(topic.slug, topic.title, topic.title, body.strip() + "\n", intro, topic.sort_order)
        written.append(topic.slug)
        if log:
            log(f"Kapitel geschrieben: {topic.title}")
    return written
