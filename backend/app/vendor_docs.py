"""Links zur Hersteller-Dokumentation.

Two sources, in this order:

1. `CURATED` -- hand-maintained landing pages for vendors and products common in German
   households. Stable, always correct, no network call needed.
2. The LLM, for everything else (see classify.py).

Source 2 is the reason `validate` exists. A language model asked for a documentation URL will
happily produce a plausible-looking one that has never existed, and a dead link in the "was tun
wenn es klemmt" chapter is worse than no link -- it sends someone chasing a 404 at exactly the
wrong moment. Every non-curated URL is therefore fetched once before it is stored, and dropped if
it doesn't answer.
"""
from __future__ import annotations

import httpx

# Matched case-insensitively against vendor + model + discovery evidence, most specific first --
# "fritz!repeater" has to win over the plain "avm" entry.
CURATED: tuple[tuple[tuple[str, ...], str, str], ...] = (
    (("fritz!repeater", "fritzrepeater", "fritz!wlan"), "AVM Service", "https://avm.de/service/"),
    (("fritz!box", "fritzbox", "avm"), "AVM FRITZ!Box Handbücher", "https://avm.de/service/handbuecher/"),
    (("synology", "diskstation"), "Synology Knowledge Center", "https://kb.synology.com/"),
    (("qnap",), "QNAP Support", "https://www.qnap.com/en/support"),
    (("proxmox",), "Proxmox VE Dokumentation", "https://pve.proxmox.com/pve-docs/"),
    (("home assistant", "hassio", "homeassistant"), "Home Assistant Dokumentation", "https://www.home-assistant.io/docs/"),
    (("unifi", "ubiquiti"), "Ubiquiti Help Center", "https://help.ui.com/"),
    (("openwrt",), "OpenWrt Dokumentation", "https://openwrt.org/docs/start"),
    (("raspberry pi", "raspberrypi"), "Raspberry Pi Dokumentation", "https://www.raspberrypi.com/documentation/"),
    (("pi-hole", "pihole"), "Pi-hole Dokumentation", "https://docs.pi-hole.net/"),
    (("nextcloud",), "Nextcloud Dokumentation", "https://docs.nextcloud.com/"),
    (("plex",), "Plex Support", "https://support.plex.tv/"),
    (("jellyfin",), "Jellyfin Dokumentation", "https://jellyfin.org/docs/"),
    (("sonos",), "Sonos Support", "https://support.sonos.com/"),
    (("philips hue", "hue bridge", "signify"), "Philips Hue Support", "https://www.philips-hue.com/de-de/support"),
    (("shelly",), "Shelly Knowledge Base", "https://kb.shelly.cloud/"),
    (("esphome",), "ESPHome Dokumentation", "https://esphome.io/"),
    (("tasmota",), "Tasmota Dokumentation", "https://tasmota.github.io/docs/"),
    (("zigbee2mqtt",), "Zigbee2MQTT Dokumentation", "https://www.zigbee2mqtt.io/"),
    (("brother",), "Brother Support", "https://support.brother.com/"),
    (("hewlett", "hp inc", "hp ", "laserjet", "officejet"), "HP Support", "https://support.hp.com/"),
    (("canon",), "Canon Support", "https://www.canon.de/support/"),
    (("epson",), "Epson Support", "https://www.epson.de/support"),
    (("netgear",), "Netgear Support", "https://www.netgear.com/support/"),
    (("tp-link", "tplink"), "TP-Link Support", "https://www.tp-link.com/de/support/"),
    (("zyxel",), "Zyxel Support", "https://support.zyxel.eu/"),
    (("devolo",), "devolo Support", "https://www.devolo.de/support"),
    (("apple", "airplay", "apple tv"), "Apple Support", "https://support.apple.com/de-de"),
    (("samsung",), "Samsung Support", "https://www.samsung.com/de/support/"),
    (("sony",), "Sony Support", "https://www.sony.de/electronics/support"),
    (("docker",), "Docker Dokumentation", "https://docs.docker.com/"),
    (("portainer",), "Portainer Dokumentation", "https://docs.portainer.io/"),
    (("grafana",), "Grafana Dokumentation", "https://grafana.com/docs/"),
    (("ollama",), "Ollama Dokumentation", "https://github.com/ollama/ollama/tree/main/docs"),
    (("fronius",), "Fronius Support", "https://www.fronius.com/de-de/germany/solarenergie/service-support-de"),
    (("vaillant",), "Vaillant Hilfe & Service", "https://www.vaillant.de/hilfe-service/"),
    (("viessmann",), "Viessmann Service", "https://www.viessmann.de/de/hilfe.html"),
    (("go-e", "go-echarger"), "go-e Support", "https://go-e.com/de-de/support"),
    (("homematic", "eq-3"), "Homematic Support", "https://www.eq-3.de/service/downloads.html"),
    (("tado",), "tado° Support", "https://support.tado.com/"),
    (("netatmo",), "Netatmo Hilfe", "https://helpcenter.netatmo.com/"),
)


def lookup(*fields: str) -> tuple[str, str]:
    """Returns (label, url) for the first curated match across the given text fields, or ("", "")."""
    haystack = " ".join(f for f in fields if f).lower()
    if not haystack.strip():
        return "", ""
    for needles, label, url in CURATED:
        if any(needle in haystack for needle in needles):
            return label, url
    return "", ""


async def validate(url: str, timeout_s: float = 6.0) -> bool:
    """True if the URL actually answers. Used only for LLM-suggested links -- curated ones are
    trusted without a network call so a scan works offline.

    A HEAD request would be cheaper but plenty of vendor sites answer 405 or 403 to it while
    serving GET fine, so this uses GET and reads nothing.
    """
    if not url.startswith(("http://", "https://")):
        return False
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(timeout_s, connect=4.0),
                                     follow_redirects=True) as client:
            response = await client.get(url, headers={"User-Agent": "HomeAtlas/1.0 (link check)"})
    except (httpx.HTTPError, OSError, ValueError):
        return False
    return response.status_code < 400
