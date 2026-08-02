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

_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Computer & Mobilgeräte", ("pc", "mobile")),
    ("Smart Home", ("smarthome", "iot")),
    ("Wärme, Klima & Energie", ("heating", "climate", "energy")),
    ("Drucker, Medien & Kameras", ("printer", "media", "camera")),
    ("Weitere Geräte", ("other", "vm")),
)


def _esc(text: str) -> str:
    return html.escape(text or "", quote=True)


def _truncate(text: str, limit: int) -> str:
    text = text or ""
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _box(x: float, y: float, w: float, h: float, title: str, subtitle: str = "",
         status: str = "", fill: str | None = None) -> str:
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
    return "".join(parts)


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
                        item.get("status", ""), item.get("fill")))
        anchors.append((x + box_w / 2, y))
    return "".join(svg), anchors


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


def render(settings: dict | None = None) -> str:
    settings = settings or db.get_settings()
    systems = db.list_systems()
    by_kind: dict[str, list[dict]] = {}
    for system in systems:
        by_kind.setdefault(system["kind"], []).append(system)

    routers = by_kind.get("router", [])
    network = by_kind.get("network", [])
    hosts = by_kind.get("server", []) + by_kind.get("nas", [])
    containers = by_kind.get("container", [])

    svg: list[str] = []
    y = 40

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

    # --- Router -------------------------------------------------------------------------
    if routers:
        svg.append(_label(40, y - 12, "Router"))
        items = [{"title": r["name"], "subtitle": r["ip"], "status": r["status"]} for r in routers[:4]]
        row_svg, anchors = _row(items, y, box_w_max=260)
        svg.append(_edges(previous, anchors))
        svg.append(row_svg)
        previous = anchors[0]
        y += _LAYER_GAP

    # --- Verteilung ---------------------------------------------------------------------
    if network:
        svg.append(_label(40, y - 12, "Verteilung (Switche, WLAN)"))
        items = [{"title": n["name"], "subtitle": n["ip"], "status": n["status"]} for n in network[:5]]
        row_svg, anchors = _row(items, y)
        svg.append(_edges(previous, anchors))
        svg.append(row_svg)
        y += _LAYER_GAP

    # --- Server / NAS, mit Containern darin ---------------------------------------------
    if hosts:
        svg.append(_label(40, y - 12, "Server und Speicher"))
        items = [{"title": h["name"], "subtitle": h["ip"], "status": h["status"]} for h in hosts[:5]]
        row_svg, anchors = _row(items, y)
        svg.append(_edges(previous, anchors))
        svg.append(row_svg)
        if containers:
            running = sum(1 for c in containers if c["status"] == "online")
            container_y = y + _BOX_H + 12
            box_w, box_x = 240, (_W - 240) / 2
            svg.append(
                f'<rect x="{box_x:.0f}" y="{container_y:.0f}" width="{box_w}" height="34" rx="8" '
                f'fill="{_COLORS["bg"]}" stroke="{_COLORS["border"]}" stroke-dasharray="4 3"/>'
                f'<text x="{_W / 2:.0f}" y="{container_y + 22:.0f}" text-anchor="middle" '
                f'fill="{_COLORS["muted"]}" font-size="12">'
                f'{len(containers)} Container, davon {running} aktiv</text>'
            )
            y += 46
        y += _LAYER_GAP

    # --- Endgeräte, gruppiert -----------------------------------------------------------
    groups = []
    for label, kinds in _GROUPS:
        members = [s for kind in kinds for s in by_kind.get(kind, [])]
        if members:
            online = sum(1 for m in members if m["status"] == "online")
            groups.append({
                "title": f"{len(members)} {label}",
                "subtitle": f"{online} erreichbar" if online else "keins erreichbar",
                "fill": _COLORS["boxAlt"],
            })
    if groups:
        svg.append(_label(40, y - 12, "Endgeräte"))
        row_svg, anchors = _row(groups, y)
        svg.append(_edges(previous, anchors))
        svg.append(row_svg)
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
