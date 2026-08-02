"""Port catalog: what a given open TCP port means, in words a non-technical reader understands.

Two jobs. `SERVICES` labels a port for the documentation ("445 -> Windows-Dateifreigabe"), and
`DEVICE_HINTS` maps the handful of ports that essentially *identify* a product (8123 is Home
Assistant, 32400 is Plex, 1400 is Sonos) to a device kind and a plain-language description. The
hints are what make the inventory useful before any LLM is configured -- and they are also fed to
the LLM as evidence, so a wrong guess there is corrected rather than compounded.
"""
from __future__ import annotations

# port -> (short technical name, plain-German explanation)
SERVICES: dict[int, tuple[str, str]] = {
    21: ("FTP", "Dateiübertragung (unverschlüsselt, veraltet)"),
    22: ("SSH", "Verschlüsselte Fernwartung über die Kommandozeile"),
    23: ("Telnet", "Unverschlüsselte Fernwartung -- sollte abgeschaltet sein"),
    25: ("SMTP", "E-Mail-Versand"),
    53: ("DNS", "Namensauflösung -- übersetzt Internetadressen in IP-Adressen"),
    80: ("HTTP", "Web-Oberfläche (unverschlüsselt)"),
    88: ("HTTP alt", "Web-Oberfläche auf einem Ausweich-Port"),
    110: ("POP3", "E-Mail-Abruf"),
    111: ("RPC", "Hilfsdienst für Dateifreigaben unter Linux"),
    135: ("MS-RPC", "Windows-interner Dienst"),
    139: ("NetBIOS", "Ältere Windows-Dateifreigabe"),
    143: ("IMAP", "E-Mail-Abruf"),
    389: ("LDAP", "Zentrale Benutzerverwaltung"),
    443: ("HTTPS", "Verschlüsselte Web-Oberfläche"),
    445: ("SMB", "Windows-Dateifreigabe -- hier liegen Netzlaufwerke"),
    502: ("Modbus", "Steuerungsprotokoll für Technik wie Wechselrichter, Heizung oder Zähler"),
    515: ("LPD", "Klassischer Druckdienst"),
    548: ("AFP", "Apple-Dateifreigabe"),
    554: ("RTSP", "Video-Livestream -- typisch für Überwachungskameras"),
    587: ("SMTP", "E-Mail-Versand (Einlieferung)"),
    631: ("IPP", "Netzwerkdruck"),
    993: ("IMAPS", "Verschlüsselter E-Mail-Abruf"),
    995: ("POP3S", "Verschlüsselter E-Mail-Abruf"),
    1400: ("Sonos", "Steuerung von Sonos-Lautsprechern"),
    1883: ("MQTT", "Nachrichten-Bus, über den viele Smart-Home-Geräte reden"),
    2049: ("NFS", "Linux-Dateifreigabe"),
    2375: ("Docker API", "Docker-Fernsteuerung -- UNVERSCHLÜSSELT, ein Sicherheitsrisiko"),
    2376: ("Docker API", "Docker-Fernsteuerung (verschlüsselt)"),
    3000: ("HTTP", "Web-Oberfläche einer Anwendung (oft Grafana oder eine Node.js-App)"),
    3306: ("MySQL", "Datenbank"),
    3389: ("RDP", "Windows-Fernsteuerung des Bildschirms"),
    5000: ("HTTP", "Web-Oberfläche (oft Synology DSM oder eine kleine App)"),
    5001: ("HTTPS", "Verschlüsselte Web-Oberfläche (oft Synology DSM)"),
    5060: ("SIP", "Internet-Telefonie"),
    5432: ("PostgreSQL", "Datenbank"),
    5900: ("VNC", "Fernsteuerung des Bildschirms"),
    6379: ("Redis", "Zwischenspeicher-Datenbank"),
    7000: ("AirPlay", "Apple-Streaming"),
    8006: ("Proxmox", "Web-Oberfläche des Proxmox-Virtualisierungsservers"),
    8008: ("Chromecast", "Google-Streaming-Steuerung"),
    8009: ("Chromecast", "Google-Streaming (Datenkanal)"),
    8080: ("HTTP alt", "Web-Oberfläche auf einem Ausweich-Port"),
    8081: ("HTTP alt", "Web-Oberfläche auf einem Ausweich-Port"),
    8096: ("Jellyfin", "Medien-Server für Filme und Serien"),
    8123: ("Home Assistant", "Zentrale des Smart-Home-Systems Home Assistant"),
    8443: ("HTTPS alt", "Verschlüsselte Web-Oberfläche auf einem Ausweich-Port"),
    8883: ("MQTT/TLS", "Verschlüsselter Nachrichten-Bus für Smart-Home-Geräte"),
    9000: ("HTTP", "Web-Oberfläche (oft Portainer zur Docker-Verwaltung)"),
    9090: ("HTTP", "Web-Oberfläche (oft Prometheus oder Cockpit)"),
    9100: ("JetDirect", "Direktdruck -- fast immer ein Netzwerkdrucker"),
    9200: ("Elasticsearch", "Suchdatenbank"),
    10000: ("Webmin", "Server-Verwaltungsoberfläche"),
    11434: ("Ollama", "Lokaler KI-Sprachmodell-Server"),
    32400: ("Plex", "Medien-Server für Filme und Serien"),
    51827: ("HomeKit", "Apple-HomeKit-Zubehörbrücke"),
}

# Ports checked in the first, fast pass just to decide "is anything there at all". Deliberately
# short: this runs against every address in the subnet, the full catalog only against hosts that
# already answered.
LIVENESS_PORTS = (80, 443, 22, 445, 53, 8080, 139, 3389, 631, 9100, 8123, 5000)

ALL_PORTS = tuple(sorted(SERVICES))

# Ports that on their own are strong evidence for a specific kind of device.
# port -> (kind, model/product guess, plain-German purpose)
DEVICE_HINTS: dict[int, tuple[str, str, str]] = {
    515: ("printer", "", "Netzwerkdrucker"),
    631: ("printer", "", "Netzwerkdrucker"),
    9100: ("printer", "", "Netzwerkdrucker"),
    554: ("camera", "", "Überwachungs- oder Türkamera"),
    1400: ("media", "Sonos", "Sonos-Lautsprecher"),
    8008: ("media", "Chromecast", "Google-Chromecast-fähiges Gerät (Fernseher oder Streaming-Stick)"),
    8009: ("media", "Chromecast", "Google-Chromecast-fähiges Gerät (Fernseher oder Streaming-Stick)"),
    32400: ("server", "Plex", "Medien-Server (Plex)"),
    8096: ("server", "Jellyfin", "Medien-Server (Jellyfin)"),
    8123: ("smarthome", "Home Assistant", "Smart-Home-Zentrale (Home Assistant)"),
    8006: ("server", "Proxmox VE", "Virtualisierungs-Server (Proxmox)"),
    5001: ("nas", "Synology", "Netzwerkspeicher (NAS)"),
    2049: ("nas", "", "Netzwerkspeicher mit Linux-Dateifreigabe"),
    502: ("climate", "", "Technikgerät mit Modbus -- z. B. Wechselrichter, Wärmepumpe oder Stromzähler"),
    11434: ("server", "Ollama", "Server mit lokalem KI-Sprachmodell"),
    1883: ("smarthome", "", "Smart-Home-Nachrichten-Bus (MQTT-Broker)"),
}


def label_for(port: int) -> tuple[str, str]:
    return SERVICES.get(port, (f"Port {port}", "Unbekannter Dienst"))


def describe_ports(open_ports: list[int]) -> list[dict]:
    """Shape the inventory and the documentation both render from."""
    return [
        {"port": p, "service": label_for(p)[0], "explanation": label_for(p)[1]}
        for p in sorted(open_ports)
    ]


def hint_from_ports(open_ports: list[int]) -> tuple[str, str, str] | None:
    """First matching hint wins, in catalog order rather than port order -- a box with both 9100
    and 80 open is a printer with a web UI, not a web server that happens to print."""
    for port in DEVICE_HINTS:
        if port in open_ports:
            return DEVICE_HINTS[port]
    return None
