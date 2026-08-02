"""Live network checks the troubleshooting assistant can run, plus the plain-German explanation
of each result.

Every one of these ends up callable by the LLM (see tools.py), so the safety properties are part
of the design rather than an afterthought:

* No shell. Every external command goes through `create_subprocess_exec` with an argument list, so
  a hostname containing `;` or backticks is a hostname, not a command.
* Arguments are validated against a strict pattern before they reach a subprocess at all.
* Every check is read-only and bounded by a timeout -- nothing here reconfigures a device, logs
  in anywhere, or runs unbounded.

The `explanation` field on each result is what the UI and the chat actually show; a layperson
needs "der Router antwortet, aber das Internet dahinter nicht" rather than a packet-loss table.
"""
from __future__ import annotations

import asyncio
import re
import shutil
import socket
import time

import httpx

# Hostnames, IPv4, and IPv6 literals -- deliberately no spaces, quotes, slashes or shell
# metacharacters. Anything else is rejected before a subprocess is spawned.
_HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,251}[A-Za-z0-9])?$")


class DiagnosticError(ValueError):
    pass


def _validate_host(host: str) -> str:
    host = (host or "").strip()
    if not _HOST_RE.match(host):
        raise DiagnosticError(f"'{host}' ist kein gültiger Hostname und keine gültige IP-Adresse.")
    return host


def _validate_port(port: int) -> int:
    try:
        port = int(port)
    except (TypeError, ValueError) as exc:
        raise DiagnosticError(f"'{port}' ist keine gültige Portnummer.") from exc
    if not 1 <= port <= 65535:
        raise DiagnosticError("Portnummern liegen zwischen 1 und 65535.")
    return port


async def _run(args: list[str], timeout: float) -> tuple[int, str]:
    if shutil.which(args[0]) is None:
        return 127, f"Das Programm '{args[0]}' ist im Container nicht installiert."
    try:
        proc = await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT
        )
    except OSError as exc:
        return 127, str(exc)
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return 124, "Zeitüberschreitung -- das Gerät hat nicht rechtzeitig geantwortet."
    return proc.returncode or 0, stdout.decode("utf-8", "replace")


# ---------------------------------------------------------------------------------------------

async def ping(host: str, count: int = 3) -> dict:
    host = _validate_host(host)
    count = max(1, min(10, int(count or 3)))
    code, output = await _run(["ping", "-c", str(count), "-W", "2", "-n", host], timeout=count * 3 + 5)
    match = re.search(r"(\d+)% packet loss", output)
    loss = int(match.group(1)) if match else (0 if code == 0 else 100)
    rtt = re.search(r"= [\d.]+/([\d.]+)/", output)
    average_ms = float(rtt.group(1)) if rtt else None

    if code == 127:
        explanation = output
    elif loss == 0:
        explanation = f"{host} ist erreichbar und antwortet zuverlässig" + (
            f" (durchschnittlich {average_ms:.0f} Millisekunden)." if average_ms else "."
        )
    elif loss < 100:
        explanation = (f"{host} antwortet, aber {loss} % der Anfragen gehen verloren. "
                       "Das deutet auf eine instabile Verbindung hin -- bei WLAN oft schlechter Empfang.")
    else:
        explanation = (f"{host} antwortet gar nicht. Das Gerät ist entweder aus, nicht im Netzwerk, "
                       "oder es blockiert solche Anfragen absichtlich (manche tun das).")
    return {"host": host, "reachable": loss < 100, "packetLossPercent": loss,
            "averageMs": average_ms, "explanation": explanation, "raw": output[:2000]}


async def dns_lookup(name: str) -> dict:
    name = _validate_host(name)
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(name, None, proto=socket.IPPROTO_TCP), timeout=6.0
        )
    except (socket.gaierror, asyncio.TimeoutError, OSError) as exc:
        return {"name": name, "resolved": False, "addresses": [],
                "explanation": (f"Der Name '{name}' lässt sich nicht in eine IP-Adresse übersetzen ({exc}). "
                                "Wenn das auch für bekannte Adressen wie google.de gilt, ist die "
                                "Namensauflösung (DNS) im Netzwerk gestört -- meist am Router.")}
    addresses = sorted({info[4][0] for info in infos})
    return {"name": name, "resolved": True, "addresses": addresses,
            "explanation": f"'{name}' wird aufgelöst zu {', '.join(addresses)}. Die Namensauflösung funktioniert."}


async def reverse_dns(ip: str) -> dict:
    ip = _validate_host(ip)
    loop = asyncio.get_running_loop()
    try:
        host, _, _ = await asyncio.wait_for(loop.run_in_executor(None, socket.gethostbyaddr, ip), timeout=5.0)
    except (OSError, asyncio.TimeoutError):
        return {"ip": ip, "hostname": "", "explanation": f"Zu {ip} ist kein Gerätename hinterlegt."}
    return {"ip": ip, "hostname": host, "explanation": f"{ip} gehört zum Gerät mit dem Namen '{host}'."}


async def check_port(host: str, port: int, timeout_s: float = 3.0) -> dict:
    host = _validate_host(host)
    port = _validate_port(port)
    from . import ports as port_catalog
    service, meaning = port_catalog.label_for(port)
    started = time.monotonic()
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout_s)
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
        elapsed = (time.monotonic() - started) * 1000
        return {"host": host, "port": port, "open": True, "service": service, "elapsedMs": round(elapsed),
                "explanation": f"Port {port} ({service} -- {meaning}) auf {host} ist offen und nimmt Verbindungen an."}
    except asyncio.TimeoutError:
        return {"host": host, "port": port, "open": False, "service": service,
                "explanation": (f"Port {port} ({service}) auf {host} antwortet nicht. Entweder läuft der Dienst "
                                "nicht, oder eine Firewall blockiert ihn stillschweigend.")}
    except OSError as exc:
        return {"host": host, "port": port, "open": False, "service": service,
                "explanation": (f"Port {port} ({service}) auf {host} ist geschlossen -- die Verbindung wurde aktiv "
                                f"abgelehnt ({exc.strerror or exc}). Der Dienst läuft dort also nicht.")}


async def http_check(url: str) -> dict:
    url = (url or "").strip()
    if not url.startswith(("http://", "https://")):
        raise DiagnosticError("Bitte eine vollständige Adresse angeben, die mit http:// oder https:// beginnt.")
    try:
        # verify=False: home devices almost universally use self-signed certificates, and a
        # certificate error would mask the actual question ("antwortet die Oberfläche?").
        async with httpx.AsyncClient(timeout=httpx.Timeout(10.0, connect=5.0), verify=False,
                                     follow_redirects=True) as client:
            started = time.monotonic()
            resp = await client.get(url)
        elapsed = (time.monotonic() - started) * 1000
    except httpx.HTTPError as exc:
        return {"url": url, "reachable": False,
                "explanation": f"Die Seite {url} ist nicht erreichbar ({exc.__class__.__name__}: {exc})."}
    title_match = re.search(r"<title[^>]*>(.*?)</title>", resp.text[:20000], re.IGNORECASE | re.DOTALL)
    title = re.sub(r"\s+", " ", title_match.group(1)).strip()[:120] if title_match else ""
    return {"url": url, "reachable": True, "status": resp.status_code, "title": title,
            "server": resp.headers.get("server", ""), "elapsedMs": round(elapsed),
            "explanation": (f"{url} antwortet mit Statuscode {resp.status_code}"
                            + (f' und dem Seitentitel "{title}"' if title else "")
                            + f" in {elapsed:.0f} Millisekunden.")}


async def traceroute(host: str, max_hops: int = 15) -> dict:
    host = _validate_host(host)
    max_hops = max(1, min(30, int(max_hops or 15)))
    code, output = await _run(
        ["traceroute", "-n", "-w", "1", "-q", "1", "-m", str(max_hops), host], timeout=max_hops * 2 + 10
    )
    if code == 127:
        return {"host": host, "hops": [], "explanation": output}
    hops = []
    for line in output.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[0].isdigit():
            hops.append({"hop": int(parts[0]), "address": parts[1]})
    return {"host": host, "hops": hops, "raw": output[:3000],
            "explanation": (f"Der Weg zu {host} führt über {len(hops)} Zwischenstationen. Die erste ist "
                            "normalerweise der eigene Router; bricht die Kette gleich danach ab, liegt das "
                            "Problem beim Internetanbieter, nicht im Heimnetz."
                            if hops else f"Zu {host} ließ sich kein Weg ermitteln.")}


async def internet_check() -> dict:
    """The check a layperson actually wants: is it the internet, the router, or just one service?
    Split into three independent layers so the answer says *where* it breaks."""
    dns_task = dns_lookup("www.google.com")
    ping_task = ping("1.1.1.1", count=2)
    dns_result, ping_result = await asyncio.gather(dns_task, ping_task, return_exceptions=True)
    dns_ok = isinstance(dns_result, dict) and dns_result.get("resolved")
    ping_ok = isinstance(ping_result, dict) and ping_result.get("reachable")

    http_ok = False
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(10.0, connect=5.0)) as client:
            resp = await client.get("https://www.gstatic.com/generate_204")
        http_ok = resp.status_code in (200, 204)
    except httpx.HTTPError:
        http_ok = False

    if dns_ok and ping_ok and http_ok:
        verdict = "Die Internetverbindung funktioniert vollständig."
    elif ping_ok and not dns_ok:
        verdict = ("Das Internet ist grundsätzlich erreichbar, aber die Namensauflösung (DNS) ist gestört: "
                   "Adressen wie google.de lassen sich nicht in IP-Adressen übersetzen. Das ist fast immer "
                   "eine Einstellung am Router.")
    elif ping_ok and dns_ok and not http_ok:
        verdict = ("Internet und Namensauflösung funktionieren, aber Webseiten werden blockiert. Ein Filter, "
                   "eine Kindersicherung oder ein Proxy könnte dazwischenfunken.")
    elif not ping_ok:
        verdict = ("Es besteht keine Verbindung ins Internet. Als Nächstes prüfen: Leuchtet am Router die "
                   "Internet-/DSL-Lampe? Wenn nicht, liegt es an der Leitung oder am Anbieter, nicht am Heimnetz.")
    else:
        verdict = "Die Internetverbindung ist nur teilweise nutzbar."

    return {"dnsWorks": dns_ok, "internetReachable": ping_ok, "websitesLoad": http_ok,
            "explanation": verdict,
            "details": {"dns": dns_result if isinstance(dns_result, dict) else str(dns_result),
                        "ping": ping_result if isinstance(ping_result, dict) else str(ping_result)}}
