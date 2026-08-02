# HomeAtlas 🧭

**Dein Zuhause, dokumentiert.**

HomeAtlas durchsucht das eigene Heimnetz, erkennt selbstständig, was darin steht, und schreibt
daraus eine nach Themen sortierte Dokumentation — in einer Sprache, die auch jemand ohne
IT-Kenntnisse versteht. Dazu kommt ein KI-Assistent, der bei Störungen nicht nur redet, sondern
selbst nachmisst: pingt, Ports prüft, die Internetverbindung in drei Schichten testet.

Läuft als Docker-Container im eigenen Netz. Keine Cloud, keine Registrierung.

---

## Was es kann

| | |
|---|---|
| **Selbstständige Erkennung** | Ping/ARP-Sweep, Portscan, Reverse-DNS, mDNS/Bonjour, UPnP/SSDP, HTTP-Banner und Docker-API — fünf unabhängige Quellen, weil keine davon allein alles sieht |
| **Verständliche Doku** | 12 Kapitel nach Themen (Internet & Router, Netzwerk, Server, Container, Smart Home, Wärme & Energie, Zugänge, Notfall …) als Markdown im Browser |
| **KI-Assistent** | Kennt das Inventar, misst live nach und führt Schritt für Schritt durch die Fehlersuche |
| **Zugangsverwaltung** | Passwörter verschlüsselt gespeichert, nie in der Doku, nie beim KI-Anbieter |
| **Zwei Rollen** | Administrator sieht und ändert alles; Mitglieder lesen die Doku und nutzen den Chat — ohne Passwörter |

Der Anbieter für die KI ist frei wählbar: **Anthropic Claude, OpenAI, Google Gemini, DeepSeek**
oder ein **lokaler Ollama-Server** (dann verlässt kein einziges Byte das Haus).

---

## Installation

### Auf dem Docker-Host (empfohlen)

```bash
git clone https://github.com/akofort/HomeAtlas.git
cd HomeAtlas
./deploy.sh                      # deployt nach 192.168.1.110, Port 8280
```

Anderes Ziel oder anderer Port:

```bash
HOMEATLAS_HOST=192.168.1.50 HOMEATLAS_PORT=8380 ./deploy.sh
```

### Direkt per docker compose

```bash
docker compose up -d --build
```

Danach: **http://<host>:8280**

### Erste Anmeldung

Beim allerersten Start wird ein Administrator angelegt und sein Passwort **einmalig** ins
Protokoll geschrieben:

```bash
docker compose logs backend | grep -A4 Anmeldedaten
```

Ein eigenes Passwort lässt sich stattdessen in `docker-compose.yml` über `ADMIN_USERNAME` /
`ADMIN_PASSWORD` vorgeben (wirkt nur, solange noch kein Benutzer existiert).

---

## Der erste Durchlauf

1. **Anmelden** und den kurzen Einrichtungsassistenten ausfüllen — Name des Zuhauses, die
   wichtigsten Geräte, die wichtigsten Konten. Alles optional und jederzeit änderbar.
2. **Einstellungen → KI-Assistent**: Anbieter wählen, Schlüssel eintragen, *Verbindung testen*.
   Ohne diesen Schritt funktioniert HomeAtlas weiter, nur ohne KI-Texte und ohne Chat.
3. **Netzwerk-Scan starten.** Der Durchlauf sucht Geräte, erkennt Dienste, fragt Docker ab, lässt
   die KI Unbekanntes einordnen und schreibt anschließend die Dokumentation neu. Dauer: wenige
   Minuten für ein typisches /24-Netz.

Von Hand gepflegte Angaben sind ab dem Moment geschützt, in dem du sie speicherst: der nächste
Scan aktualisiert nur noch die veränderlichen Fakten (IP, Zustand, offene Ports) und lässt Name,
Standort und Beschreibung unangetastet. Gleiches gilt für Doku-Seiten — eine von Hand bearbeitete
Seite wird nicht mehr überschrieben (in der Oberfläche als *von Hand bearbeitet* markiert; über
*Neu erzeugen* lässt sich das zurücknehmen).

---

## Architektur

```
                    ┌──────────────────────────────────────────────┐
Browser ── :8280 ──▶│ nginx (Frontend, React + TypeScript)         │
                    │   └─ /api/* ──▶ 127.0.0.1:8000               │
                    └──────────────────────────────────────────────┘
                                        │
                    ┌───────────────────▼──────────────────────────┐
                    │ FastAPI-Backend (Host-Netz)                  │
                    │   discovery ─ ping/ARP, Ports, mDNS, SSDP    │
                    │   docker_probe ─ /var/run/docker.sock (ro)   │
                    │   classify ─ KI-Einordnung unbekannter Geräte│
                    │   docs ─ Markdown-Kapitel                    │
                    │   tools ─ Werkzeuge für den Assistenten      │
                    │   SQLite + Fernet-verschlüsselte Zugänge     │
                    └──────────────────────────────────────────────┘
```

**Warum Host-Netzwerk?** Discovery liest die ARP-Tabelle des Hosts und verschickt Multicast
(mDNS/SSDP). Über ein Docker-Bridge-Netz käme davon nichts an — die App würde nur das
Docker-Netz sehen, nie das echte Heimnetz. Deshalb bindet das Backend bewusst nur an
`127.0.0.1`: nginx ist das Einzige, was es erreicht.

---

## Sicherheit

Diese App speichert absichtlich Router-, NAS- und WLAN-Passwörter. Deshalb hier offen, was sie
schützt und was nicht:

**Verschlüsselung.** Zugangsdaten liegen Fernet-verschlüsselt in der Datenbank. Der Schlüssel
liegt im selben Docker-Volume. Das schützt gegen eine **abhandengekommene Datenbankkopie**
(Backup, `docker cp`, versehentlicher Dump) — **nicht** gegen jemanden, der bereits root auf dem
Docker-Host ist, denn der liest auch die Schlüsseldatei. Die Alternative wäre eine Passphrase bei
jedem Containerstart, was einen unbeaufsichtigten Neustart unmöglich machte.

**Die KI sieht keine Passwörter.** Das Werkzeug `list_accounts` gibt Bezeichnung, Benutzername
und Notiz zurück und streicht das Passwort — auch wenn das Modell „vertrauenswürdig" ist. Ein
Passwort im Prompt landet im Protokoll des Anbieters, im Chatverlauf und in jedem künftigen
Kontextfenster. Der Assistent kann sagen, *wo* ein Zugang hinterlegt ist; ansehen muss ihn der
Mensch in der App.

**Passwörter verlassen den Server einzeln.** API-Schlüssel kommen maskiert zurück, ein
gespeichertes Passwort nur über `GET /api/accounts/{id}/secret` — genau eines, nur für
Administratoren. Es gibt keine Route, die den Zugangsspeicher im Klartext ausgibt.

**Diagnose-Werkzeuge ohne Shell.** Alles, was der Assistent ausführen kann, ist lesend, hat ein
Timeout und läuft über `create_subprocess_exec` mit Argumentliste. Ein Hostname mit `;` oder
Backticks ist ein Hostname, kein Befehl — und wird vorher gegen ein striktes Muster geprüft.

**Der Docker-Socket ist root-äquivalent.** Read-only eingebunden und es werden ausschließlich
GET-Endpunkte aufgerufen — aber wer den Socket lesen kann, kann auf dem Host viel. Wem das zu
weit geht, entfernt die Zeile in `docker-compose.yml`; alles außer der Container-Erkennung
funktioniert weiter.

**Kein HTTPS out of the box.** HomeAtlas ist für den Betrieb im eigenen LAN gedacht. Wer es von
außen erreichbar macht, gehört hinter einen Reverse Proxy mit TLS — und sollte sich vorher
überlegen, ob das wirklich sein muss.

---

## Wie die Erkennung funktioniert

| Quelle | Was sie beiträgt |
|---|---|
| **Ping + ARP** | Findet als Einzige Geräte, die sonst nichts beantworten. Selbst ein Host, der ICMP ignoriert, taucht in der Neighbour-Tabelle auf — die ARP-Auflösung passiert *vor* dem Ping |
| **Portscan** | Sagt, was ein Gerät *tut* — und über `ports.DEVICE_HINTS` oft, was es *ist* (9100 → Drucker, 8123 → Home Assistant, 1400 → Sonos) |
| **Reverse-DNS** | Der Router kennt meist die DHCP-Namen |
| **mDNS + SSDP/UPnP** | Die mit Abstand beste Quelle für Consumer-Technik: Drucker, Fernseher, Lautsprecher und Smart-Home-Zentralen nennen ihren eigenen Namen, Hersteller und Modell |
| **Docker-API** | Image, Compose-Projekt, Volumes, Port-Weiterleitungen, Neustart-Verhalten — genau die Fakten, die man ein halbes Jahr später sucht |

Die Namensgebung folgt einer festen Rangfolge: Selbstauskunft (UPnP `friendlyName`, dann
mDNS-Name) vor DNS-Hostname vor Webseiten-Titel vor „Hersteller + letztes IP-Oktett". Die
KI-Einordnung läuft erst danach und nur über Geräte, die die Regeln nicht sicher zuordnen
konnten — ein eindeutig erkannter FRITZ!Box kostet keine Tokens. Antworten mit niedriger
Konfidenz werden verworfen: die regelbasierte Vermutung ist besser als ein Schulterzucken.

---

## Konfiguration

| Umgebungsvariable | Standard | Bedeutung |
|---|---|---|
| `HOMEATLAS_PORT` | `8280` | Port, auf dem die Oberfläche lauscht |
| `HOMEATLAS_DB_PATH` | `/data/homeatlas.db` | SQLite-Datenbank |
| `HOMEATLAS_KEY_PATH` | `/data/secret.key` | Verschlüsselungsschlüssel (wird automatisch erzeugt) |
| `HOMEATLAS_OUI_PATH` | `/data/oui.json` | Zwischenspeicher der IEEE-Herstellerdatenbank |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD` | — | Erstes Konto vorgeben statt generieren lassen |
| `TZ` | `Europe/Berlin` | Zeitzone für Anzeigen und Protokolle |

Scan-Verhalten (Bereiche, Ausnahmen, Timeouts, welche Quellen aktiv sind, ob die KI mitarbeitet)
wird in der Oberfläche unter *Einstellungen → Netzwerk-Scan* gepflegt.

---

## Entwicklung

```bash
# Backend
cd backend
pip install -r requirements.txt
HOMEATLAS_DB_PATH=./dev.db HOMEATLAS_KEY_PATH=./dev.key ADMIN_PASSWORD=devpass123 \
  uvicorn app.main:app --reload --port 8000

# Frontend (proxyt /api automatisch auf :8000)
cd frontend
npm install
npm run dev
```

Unter Windows fehlen `ip`, `ping` und `traceroute` in der Container-Form — Discovery und Diagnose
sind dort eingeschränkt, die Oberfläche und alles andere funktionieren.

---

## Bekannte Grenzen

- **Nur IPv4.** IPv6-Geräte tauchen auf, wenn sie sich per mDNS/SSDP melden, werden aber nicht
  aktiv gescannt.
- **Netzbereiche bis /22.** Ein größerer Bereich wird auf die ersten 1024 Adressen begrenzt —
  ein versehentliches /16 wären 65.000 Hosts und ein praktisch endloser Scan.
- **Zufällige MAC-Adressen.** Moderne Telefone wechseln ihre Netzwerkkennung regelmäßig und
  können deshalb mehrfach im Inventar erscheinen. Solche Geräte sind intern als
  `randomizedMac` markiert.
- **Hersteller-Datenbank.** Ohne die IEEE-Liste (wird beim ersten Scan automatisch geladen, sonst
  manuell in den Einstellungen) ist die Herstellererkennung auf eine kleine, handgepflegte Liste
  beschränkt.

---

## Lizenz

Privates Projekt.
