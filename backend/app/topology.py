"""Basis-Übersichtsplan des Heimnetzes als SVG.

Rendered server-side rather than with a diagram library in the browser: the layout is a fixed set
of layers (Internet → Router → Verteilung → Server → Endgeräte), so a general-purpose graph engine
would add a megabyte of JavaScript to draw something this file can place deterministically.

Readability decisions, since this is meant for someone who does not read network diagrams:

* Individually named boxes only where the name matters -- router, switches/APs, servers, NAS.
  Everything else is grouped and counted ("14 Computer & Mobilgeräte"), because forty labelled
  boxes is a picture nobody looks at twice.
* Containers are drawn inside their host, not as peers, which is where they actually live.
* Colour carries status (reachable / not reachable), and is never the only signal -- the box also
  says so in words.
"""
from __future__ import annotations

import html
import re

from . import db

_W = 1000
_BOX_H = 52
_GAP_X = 16
_LAYER_GAP = 78

_COLORS = {
    "bg": "#0b1120",
    "box": "#131c31",
    "boxAlt": "#1b2540",
    "border": "#26304a",
    "text": "#e8edf7",
    "muted": "#94a3b8",
    "line": "#3b4767",
    "ok": "#34d399",
    "down": "#f87171",
    "accent": "#38bdf8",
}

def _esc(text: str) -> str:
    return html.escape(text or "", quote=True)


def _truncate(text: str, limit: int) -> str:
    text = text or ""
    return text if len(text) <= limit else text[: limit - 1] + "…"


# ---------------------------------------------------------------------------------------------
# LLDP neighbour resolution -- turns the raw text facts probe_auth.py already collects (Mikrotik
# `/ip neighbor print`, Aruba `show lldp info remote-device`, Cisco `show cdp neighbors detail`,
# generic SNMP LLDP-MIB walks) into
# actual edges between two systems already in the inventory, so "important devices" below can be
# connected the way they are actually wired instead of only guessed from `kind`.
#
# None of these three formats has been verified against real hardware -- see probe_auth.py's own
# command sets, which have the same caveat. The parsers below are deliberately defensive: regex-
# based rather than fixed column positions, and a neighbour that cannot be matched to a known
# system (by MAC, falling back to name) simply yields no edge rather than a wrong one. A rendering
# with zero resolved links still falls back to the pre-LLDP trunk connection (see render()), so a
# format mismatch degrades the plan, it does not break it.
# ---------------------------------------------------------------------------------------------

_MAC_RE = re.compile(r"\b([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b")


def _normalize_mac(mac: str) -> str:
    return re.sub(r"[^0-9A-Fa-f]", "", mac).lower()


def _parse_mikrotik_neighbors(text: str) -> list[dict]:
    """RouterOS `print detail` output: one record per line/wrapped-block, `key=value` pairs
    (`key="quoted value"` when the value contains spaces). Extracts `mac-address` and `identity`
    per record via a line-oriented regex rather than assuming a fixed field order or wrapping."""
    neighbors = []
    for block in re.split(r"\n(?=\s*\d+\s+\S+=)", text):
        mac_match = re.search(r"mac-address=([0-9A-Fa-f:]{17})", block, re.IGNORECASE)
        name_match = re.search(r'identity="([^"]*)"|identity=(\S+)', block)
        mac = mac_match.group(1) if mac_match else None
        name = (name_match.group(1) or name_match.group(2)) if name_match else None
        if mac or name:
            neighbors.append({"mac": mac, "name": name})
    return neighbors


def _parse_aruba_neighbors(text: str) -> list[dict]:
    """ArubaOS-Switch `show lldp info remote-device`: a header row containing "ChassisId" marks
    where the table starts; each following non-separator line is tokenized on runs of 2+ spaces.
    Chassis IDs are commonly printed as space-separated hex octets rather than colon-separated."""
    lines = text.splitlines()
    header_index = next((i for i, line in enumerate(lines) if "ChassisId" in line or "SysName" in line), None)
    if header_index is None:
        return []
    neighbors = []
    for line in lines[header_index + 1:]:
        if not line.strip() or set(line.strip()) <= {"-", "+", " "}:
            continue
        # "|" is a column separator here, not data -- turned into a hard split point first so it
        # never ends up glued to the next cell regardless of how much whitespace surrounds it.
        cells = [c.strip() for c in re.split(r"\s{2,}|\|", line.strip()) if c.strip()]
        if not cells:
            continue
        mac = None
        for cell in cells:
            hex_octets = cell.split()
            if len(hex_octets) == 6 and all(re.fullmatch(r"[0-9A-Fa-f]{2}", o) for o in hex_octets):
                mac = ":".join(hex_octets)
                break
            mac_match = _MAC_RE.search(cell)
            if mac_match:
                mac = mac_match.group(0)
                break
        # The system name is conventionally the last column and the only one that is not the
        # chassis id, a bare port number, or a port description -- take the last non-empty,
        # non-MAC-shaped cell as a best-effort guess.
        name = next((c for c in reversed(cells) if c != mac and not re.fullmatch(r"[\w/.-]{1,4}", c)), None)
        if mac or name:
            neighbors.append({"mac": mac, "name": name})
    return neighbors


def _parse_cisco_neighbors(text: str) -> list[dict]:
    """Cisco IOS `show cdp neighbors detail`: entries are separated by a dashed rule line, each
    carrying a `Device ID: <name>` line. Unlike the LLDP-based formats above, CDP detail output
    does not include the neighbour's chassis MAC, so entries here only ever resolve by name."""
    neighbors = []
    for block in re.split(r"\n-{5,}\n", text):
        name_match = re.search(r"Device ID:\s*(\S+)", block)
        if name_match:
            neighbors.append({"mac": None, "name": name_match.group(1)})
    return neighbors


def _parse_snmp_lldp(text: str) -> list[dict]:
    """Generic SNMP LLDP-MIB walk output (`snmpwalk`), one line per `OID = TYPE: value`. Groups
    lines by their trailing `timeMark.localPort.index` OID suffix (standardised by the MIB, so
    this grouping is reliable even though the exact column-to-field mapping is not hardcoded
    here) and classifies each line's value within a group by shape: a hex string of six octets is
    treated as the chassis MAC, a quoted string containing letters as the candidate system name."""
    groups: dict[str, dict] = {}
    for line in text.splitlines():
        match = re.match(r"(\S+)\s*=\s*(\S+):\s*(.*)", line.strip())
        if not match:
            continue
        oid, value_type, raw_value = match.groups()
        # Grouping key is the trailing timeMark.localPort.index (the last three numeric OID
        # components), NOT the column number right before them -- two lines from the same
        # neighbour entry differ only in which column they report, so including the column in the
        # key would put them in different groups instead of merging them.
        parts = [p for p in oid.split(".") if p.isdigit()]
        if len(parts) < 3:
            continue
        suffix = ".".join(parts[-3:])
        group = groups.setdefault(suffix, {"mac": None, "name": None})
        if "Hex-STRING" in value_type or re.fullmatch(r"([0-9A-Fa-f]{2}\s*){6}", raw_value.strip()):
            octets = raw_value.split()
            if len(octets) == 6:
                group["mac"] = ":".join(octets)
        elif "STRING" in value_type:
            candidate = raw_value.strip().strip('"')
            if candidate and re.search(r"[A-Za-z]", candidate) and not group["name"]:
                group["name"] = candidate
    return [g for g in groups.values() if g["mac"] or g["name"]]


def _neighbors_for_system(system: dict) -> list[dict]:
    """Reads whatever probe_auth.py already stored in `extra.probe` for this system and picks the
    matching parser by which fact carries the neighbour data -- `"neighbors"` for the Mikrotik/
    Aruba/Cisco SSH command sets, `"lldpNeighbors"` for the SNMP one."""
    probe = (system.get("extra") or {}).get("probe") or {}
    neighbors: list[dict] = []
    for source, result in probe.items():
        facts = (result or {}).get("facts") or {}
        if "neighbors" in facts:
            text = facts["neighbors"]["value"]
            if source.startswith("ssh:") and "identity=" in text:
                parser = _parse_mikrotik_neighbors
            elif "Device ID:" in text:
                parser = _parse_cisco_neighbors
            else:
                parser = _parse_aruba_neighbors
            neighbors += parser(text)
        if "lldpNeighbors" in facts:
            neighbors += _parse_snmp_lldp(facts["lldpNeighbors"]["value"])
    return neighbors


def _resolve_system_links(systems: list[dict]) -> dict[str, set[str]]:
    """One MAC->id and name->id index built once, then each system's parsed neighbours are
    resolved against it (MAC first, name as fallback, both case/format-insensitive). Only pairs
    where BOTH ends resolve to a known system produce an edge -- an unresolvable neighbour is
    simply not drawn, never guessed at."""
    by_mac = {_normalize_mac(s["mac"]): s["id"] for s in systems if s.get("mac")}
    by_name = {s["name"].strip().lower(): s["id"] for s in systems if s.get("name")}

    links: dict[str, set[str]] = {}
    for system in systems:
        for neighbor in _neighbors_for_system(system):
            target_id = None
            if neighbor.get("mac"):
                target_id = by_mac.get(_normalize_mac(neighbor["mac"]))
            if target_id is None and neighbor.get("name"):
                target_id = by_name.get(neighbor["name"].strip().lower())
            if target_id is None or target_id == system["id"]:
                continue
            links.setdefault(system["id"], set()).add(target_id)
            links.setdefault(target_id, set()).add(system["id"])
    return links


def _box(x: float, y: float, w: float, h: float, title: str, subtitle: str = "",
         status: str = "", fill: str | None = None, system_id: str | None = None,
         expandable: bool = False) -> str:
    accent = _COLORS["ok"] if status == "online" else _COLORS["down"] if status == "offline" else _COLORS["border"]
    chars = max(6, int(w / 7.2))
    parts = [
        f'<rect x="{x:.0f}" y="{y:.0f}" width="{w:.0f}" height="{h:.0f}" rx="10" '
        f'fill="{fill or _COLORS["box"]}" stroke="{accent}" stroke-width="1.5"/>',
        f'<text x="{x + w / 2:.0f}" y="{y + (20 if subtitle else h / 2 + 4):.0f}" text-anchor="middle" '
        f'fill="{_COLORS["text"]}" font-size="13" font-weight="600">{_esc(_truncate(title, chars))}</text>',
    ]
    if subtitle:
        parts.append(
            f'<text x="{x + w / 2:.0f}" y="{y + 37:.0f}" text-anchor="middle" '
            f'fill="{_COLORS["muted"]}" font-size="11">{_esc(_truncate(subtitle, chars + 4))}</text>'
        )
    body = "".join(parts)
    if not system_id:
        return body
    # Expandable boxes (a host with containers/VMs nested in it) are wrapped so the frontend can
    # find them by a click and navigate to the filtered device list -- the plan stays a single
    # static SVG (see module docstring) and does not itself re-layout on click.
    attrs = f'data-system-id="{_esc(system_id)}"'
    if expandable:
        attrs += ' data-expand="1" style="cursor:pointer"'
    return f'<g {attrs}>{body}</g>'


def _row(items: list[dict], y: float, box_w_max: float = 200) -> tuple[str, list[tuple[float, float]]]:
    """Lays out one centred row. Returns (svg, [(centre_x, y) …]) so the caller can draw edges."""
    if not items:
        return "", []
    count = len(items)
    box_w = min(box_w_max, (_W - 80 - _GAP_X * (count - 1)) / count)
    total = count * box_w + _GAP_X * (count - 1)
    start = (_W - total) / 2
    svg, anchors = [], []
    for index, item in enumerate(items):
        x = start + index * (box_w + _GAP_X)
        svg.append(_box(x, y, box_w, _BOX_H, item["title"], item.get("subtitle", ""),
                        item.get("status", ""), item.get("fill"), item.get("id"), item.get("expand", False)))
        anchors.append((x + box_w / 2, y))
    return "".join(svg), anchors


def _chain_layers(items: list[dict]) -> list[list[dict]]:
    """Groups items into generations by `parentId` within the same list -- e.g. a secondary
    router (Mikrotik) plugged into the primary one (FritzBox) renders one row below it instead of
    beside it, matching how the household actually wired it rather than a flat guess."""
    ids = {i["id"] for i in items}
    by_parent: dict[str | None, list[dict]] = {}
    for item in items:
        parent = item.get("parentId") if item.get("parentId") in ids else None
        by_parent.setdefault(parent, []).append(item)
    layers: list[list[dict]] = []
    frontier = by_parent.get(None, [])
    placed: set[str] = set()
    while frontier:
        layers.append(frontier)
        placed.update(i["id"] for i in frontier)
        frontier = [child for parent in frontier for child in by_parent.get(parent["id"], [])]
    # Anything left over is an orphaned chain (e.g. a parentId cycle from bad data) -- still show
    # it rather than silently dropping a device from the plan.
    leftover = [i for i in items if i["id"] not in placed]
    if leftover:
        layers.append(leftover)
    return layers


def _edges_by_parent(anchor_by_id: dict[str, tuple[float, float]], layer: list[dict],
                     anchors: list[tuple[float, float]], fallback_top: tuple[float, float]) -> str:
    """Like `_edges`, but each item connects to its own parent's anchor (falling back to
    `fallback_top` for items with no parent in this diagram) instead of one shared trunk.

    `anchors` must be `layer`'s own just-computed anchors (parallel by index, straight from
    `_row()`) -- NOT looked up via `anchor_by_id`, because the caller adds this row's own ids to
    `anchor_by_id` only *after* drawing it (same order the router-chain loop already used), so at
    call time `anchor_by_id` never contains them yet. Looking them up there instead of taking them
    as a parameter silently produced empty edge lists -- boxes drew, connecting lines did not."""
    groups: dict[str, list[tuple[float, float]]] = {}
    for item, anchor in zip(layer, anchors):
        key = item.get("parentId") if item.get("parentId") in anchor_by_id else "__root__"
        groups.setdefault(key, []).append(anchor)
    svg = []
    for key, bottoms in groups.items():
        top = anchor_by_id.get(key, fallback_top)
        svg.append(_edges(top, bottoms))
    return "".join(svg)


def _edges(top: tuple[float, float], bottoms: list[tuple[float, float]]) -> str:
    """Orthogonal connectors from one box's bottom edge to the top edge of each box below."""
    if not bottoms:
        return ""
    top_x, top_y = top
    mid_y = top_y + _BOX_H + (_LAYER_GAP - _BOX_H) / 2
    paths = [f'<path d="M {top_x:.0f} {top_y + _BOX_H:.0f} V {mid_y:.0f}" '
             f'stroke="{_COLORS["line"]}" stroke-width="1.5" fill="none"/>']
    xs = [x for x, _ in bottoms]
    if len(xs) > 1:
        paths.append(f'<path d="M {min(xs):.0f} {mid_y:.0f} H {max(xs):.0f}" '
                     f'stroke="{_COLORS["line"]}" stroke-width="1.5" fill="none"/>')
    for x, y in bottoms:
        paths.append(f'<path d="M {x:.0f} {mid_y:.0f} V {y:.0f}" '
                     f'stroke="{_COLORS["line"]}" stroke-width="1.5" fill="none"/>')
    return "".join(paths)


def _label(x: float, y: float, text: str) -> str:
    return (f'<text x="{x:.0f}" y="{y:.0f}" fill="{_COLORS["muted"]}" font-size="11" '
            f'letter-spacing="0.08em" font-weight="700">{_esc(text.upper())}</text>')


def _midpoint(anchors: list[tuple[float, float]]) -> tuple[float, float]:
    return (sum(x for x, _ in anchors) / len(anchors), anchors[0][1])


def render(settings: dict | None = None) -> str:
    settings = settings or db.get_settings()
    systems = db.list_systems()
    by_kind: dict[str, list[dict]] = {}
    for system in systems:
        by_kind.setdefault(system["kind"], []).append(system)

    routers = by_kind.get("router", [])
    network = by_kind.get("network", [])

    svg: list[str] = []
    y = 40
    # Anchors of every backbone/important box placed so far, kept across layers (not reset per
    # section) so a later "Wichtige Geräte" row can point a resolved LLDP edge at a specific
    # router or switch instead of only the generic trunk below it.
    anchor_by_id: dict[str, tuple[float, float]] = {}

    # --- Internet -----------------------------------------------------------------------
    svg.append(_label(40, y - 12, "Internet"))
    internet_svg, internet_anchor = _row([{
        "title": "Internet",
        "subtitle": settings.get("homeName") and f"Zugang für {settings['homeName']}" or "",
        "fill": _COLORS["boxAlt"],
    }], y, box_w_max=220)
    svg.append(internet_svg)
    previous = internet_anchor[0]
    y += _LAYER_GAP

    # --- Router, chained by parentId (Internet -> FritzBox -> Mikrotik -> …) ------------
    if routers:
        svg.append(_label(40, y - 12, "Router"))
        leaf_anchors: list[tuple[float, float]] = []
        for depth, layer in enumerate(_chain_layers(routers[:6])):
            items = [{"id": r["id"], "title": r["name"], "subtitle": r["ip"], "status": r["status"]}
                     for r in layer]
            row_svg, anchors = _row(items, y, box_w_max=260)
            svg.append(_edges(previous, anchors) if depth == 0
                      else _edges_by_parent(anchor_by_id, layer, anchors, previous))
            svg.append(row_svg)
            anchor_by_id.update(zip((r["id"] for r in layer), anchors))
            leaf_anchors = anchors
            y += _LAYER_GAP
        previous = _midpoint(leaf_anchors)

    # --- Verteilung ---------------------------------------------------------------------
    if network:
        svg.append(_label(40, y - 12, "Verteilung (Switche, WLAN)"))
        items = [{"id": n["id"], "title": n["name"], "subtitle": n["ip"], "status": n["status"]}
                 for n in network[:5]]
        row_svg, anchors = _row(items, y)
        svg.append(_edges(previous, anchors))
        svg.append(row_svg)
        anchor_by_id.update(zip((n["id"] for n in network[:5]), anchors))
        previous = _midpoint(anchors)
        y += _LAYER_GAP

    # --- Wichtige Geräte: alles mit Bedeutung "kritisch" ---------------------------------
    # Everything else (including non-critical servers/NAS and all end devices) lives in the
    # collapsible, kind-grouped lists PlanPage.tsx renders below the plan -- this file only ever
    # draws what someone marked as mattering, plus the backbone that carries it.
    critical = [s for s in systems if s.get("importance") == "critical" and s["kind"] not in ("container", "vm")]
    host_ids = {s["id"] for s in systems if s["kind"] in ("server", "nas")}
    children_by_host: dict[str, list[dict]] = {}
    for kind in ("container", "vm"):
        for s in by_kind.get(kind, []):
            parent = s.get("parentId")
            if parent in host_ids:
                children_by_host.setdefault(parent, []).append(s)

    if critical:
        svg.append(_label(40, y - 12, "Wichtige Geräte"))
        # Real, discovered connections where LLDP data resolved them (see _resolve_system_links);
        # a device whose neighbour isn't already anchored above (router/switch) falls back to the
        # plain trunk connection below, so a parsing miss loses a specific line, never the device.
        links = _resolve_system_links(systems)
        items = []
        for s in critical[:8]:
            subtitle = s["ip"]
            expand = False
            if s["id"] in host_ids:
                children = children_by_host.get(s["id"], [])
                if children:
                    running = sum(1 for c in children if c["status"] == "online")
                    subtitle = f'{s["ip"]} · {len(children)} Container/VM, {running} aktiv ▸'
                    expand = True
            resolved_parent = next((nid for nid in links.get(s["id"], ()) if nid in anchor_by_id), None)
            items.append({"id": s["id"], "parentId": resolved_parent, "title": s["name"],
                         "subtitle": subtitle, "status": s["status"], "expand": expand})
        row_svg, anchors = _row(items, y)
        svg.append(_edges_by_parent(anchor_by_id, items, anchors, previous))
        svg.append(row_svg)
        anchor_by_id.update(zip((s["id"] for s in critical[:8]), anchors))
        y += _LAYER_GAP

    if len(systems) == 0:
        svg.append(
            f'<text x="{_W / 2:.0f}" y="{y:.0f}" text-anchor="middle" fill="{_COLORS["muted"]}" '
            f'font-size="14">Noch keine Geräte erfasst — ein Netzwerk-Scan füllt diesen Plan.</text>'
        )
        y += 40

    height = y + 20
    legend_y = height - 26
    legend = (
        f'<circle cx="44" cy="{legend_y - 4:.0f}" r="5" fill="{_COLORS["ok"]}"/>'
        f'<text x="56" y="{legend_y:.0f}" fill="{_COLORS["muted"]}" font-size="11">erreichbar</text>'
        f'<circle cx="150" cy="{legend_y - 4:.0f}" r="5" fill="{_COLORS["down"]}"/>'
        f'<text x="162" y="{legend_y:.0f}" fill="{_COLORS["muted"]}" font-size="11">nicht erreichbar</text>'
    )

    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {_W} {height:.0f}" '
        f'width="100%" role="img" aria-label="Übersichtsplan des Heimnetzes" '
        f'font-family="Segoe UI, system-ui, sans-serif">'
        f'<rect width="{_W}" height="{height:.0f}" fill="{_COLORS["bg"]}"/>'
        f'{"".join(svg)}{legend}</svg>'
    )
