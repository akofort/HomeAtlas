import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api, type DnsResult, type MonitorState, type System } from "../lib/api";
import { useAuth } from "../App";
import { KindIcon } from "../lib/icons";

/** Alles, was der Plan oben NICHT einzeln zeichnet (siehe topology.py: nur Router/Netzwerk als
 *  Backbone, plus was als "kritisch" markiert ist) landet hier ausklappbar, gruppiert nach Art --
 *  dieselbe Aufteilung, die topology.py früher als Zählboxen ins SVG gemalt hat. */
const DEVICE_GROUPS: [string, string[]][] = [
  ["Server & Speicher", ["server", "nas"]],
  ["Container & VMs", ["container", "vm"]],
  ["Computer & Mobilgeräte", ["pc", "mobile"]],
  ["Smart Home", ["smarthome", "iot"]],
  ["Wärme, Klima & Energie", ["heating", "climate", "energy"]],
  ["Drucker, Medien & Kameras", ["printer", "media", "camera"]],
  ["Weitere Geräte", ["other"]],
];

/** Netzplan, Live-Überwachung und Diagnose auf einer Seite — die drei Dinge, die man ansieht,
 *  wenn man wissen will, wie es dem Netz gerade geht. */
export default function PlanPage() {
  const { isAdmin } = useAuth();
  const navigate = useNavigate();
  const [svg, setSvg] = useState("");
  const [systems, setSystems] = useState<System[]>([]);
  const [monitor, setMonitor] = useState<MonitorState | null>(null);
  const [dns, setDns] = useState<DnsResult | null>(null);
  const [checking, setChecking] = useState("");
  const [error, setError] = useState("");
  const timer = useRef<number | null>(null);

  const loadMonitor = useCallback(async () => {
    try {
      setMonitor(await api.monitor());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  useEffect(() => {
    // The SVG is fetched as text rather than put in an <img src>: an <img> would need its own
    // authenticated request, and inline markup can inherit the page's colours.
    fetch("/api/topology.svg", { credentials: "same-origin" })
      .then((r) => (r.ok ? r.text() : Promise.reject(new Error("Plan nicht verfügbar"))))
      .then(setSvg)
      .catch((e) => setError(e.message));
    api.listSystems().then((r) => setSystems(r.systems)).catch((e) => setError(e.message));
    void loadMonitor();
  }, [loadMonitor]);

  // Alles, was oben im Plan schon als Backbone (Router/Netzwerk) oder als "wichtiges Gerät"
  // (Bedeutung "kritisch") gezeichnet wird, taucht hier nicht noch einmal auf -- siehe
  // topology.py's render() für die exakt gespiegelte Regel.
  const groupedSystems = DEVICE_GROUPS.map(([label, kinds]) => ({
    label,
    members: systems.filter((s) => kinds.includes(s.kind) && s.importance !== "critical"),
  })).filter((g) => g.members.length > 0);

  // Poll while the tab is visible. A background tab that keeps hitting the API every few seconds
  // for hours is exactly the behaviour that drains a laptop battery for nothing.
  useEffect(() => {
    function schedule() {
      if (timer.current) window.clearInterval(timer.current);
      if (document.visibilityState !== "visible") return;
      const seconds = Math.max(5, monitor?.intervalSeconds ?? 10);
      timer.current = window.setInterval(() => void loadMonitor(), seconds * 1000);
    }
    schedule();
    document.addEventListener("visibilitychange", schedule);
    return () => {
      if (timer.current) window.clearInterval(timer.current);
      document.removeEventListener("visibilitychange", schedule);
    };
  }, [monitor?.intervalSeconds, loadMonitor]);

  async function runDns() {
    setChecking("dns");
    try {
      setDns((await api.dnsCheck()).result);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setChecking("");
    }
  }

  // Hosts with containers/VMs are drawn once, marked `data-expand`, and get their children one
  // click away instead of nested boxes -- see topology.py for why (forty container boxes is not
  // a picture anyone reads).
  function handlePlanClick(e: React.MouseEvent<HTMLDivElement>) {
    const target = (e.target as Element).closest('[data-expand="1"]');
    const id = target?.getAttribute("data-system-id");
    if (id) navigate(`/geraete?parentId=${id}`);
  }

  async function runMonitorNow() {
    setChecking("monitor");
    try {
      await api.monitorRunNow();
      await loadMonitor();
    } finally {
      setChecking("");
    }
  }

  const offline = monitor?.systems.filter((s) => s.status === "offline") ?? [];

  return (
    <>
      <div className="page-header">
        <div>
          <h1>Netzplan und Diagnose</h1>
          <p>
            Wie das Heimnetz aufgebaut ist, welche wichtigen Geräte gerade erreichbar sind und ob
            die Namensauflösung funktioniert.
          </p>
        </div>
        <div className="row">
          <button className="secondary" onClick={() => void runDns()} disabled={checking !== ""}>
            {checking === "dns" ? "Prüfe…" : "DNS testen"}
          </button>
          {isAdmin && (
            <button className="secondary" onClick={() => void runMonitorNow()} disabled={checking !== ""}>
              {checking === "monitor" ? "Prüfe…" : "Jetzt prüfen"}
            </button>
          )}
        </div>
      </div>

      {error && <div className="notice error">{error}</div>}

      {offline.length > 0 && (
        <div className="notice error">
          <strong>{offline.length} überwachte{offline.length === 1 ? "s Gerät ist" : " Geräte sind"} nicht erreichbar:</strong>{" "}
          {offline.map((s) => s.name).join(", ")}
        </div>
      )}

      <div className="card">
        <h2>Übersichtsplan</h2>
        <p className="muted" style={{ marginTop: -6 }}>
          Internet, Router, Verteilung, dann als Nächstes die als „kritisch" markierten Geräte —
          soweit bekannt mit ihrer tatsächlichen Verbindung (per LLDP erkannt), sonst am Netz
          angehängt. Alles andere steht ausklappbar darunter. Kritische Server mit Container/VMs
          zeigen nur sich selbst — ein Klick auf den Kasten öffnet die zugehörigen virtuellen Systeme.
        </p>
        {svg ? (
          <div className="table-wrap" onClick={handlePlanClick} dangerouslySetInnerHTML={{ __html: svg }} />
        ) : (
          <span className="spinner" />
        )}

        {groupedSystems.length > 0 && (
          <div style={{ marginTop: 16 }}>
            {groupedSystems.map(({ label, members }) => {
              const online = members.filter((m) => m.status === "online").length;
              return (
                <details key={label} style={{ marginBottom: 8 }}>
                  <summary style={{ cursor: "pointer", padding: "6px 0" }}>
                    <strong>{members.length}</strong> {label} — {online > 0 ? `${online} erreichbar` : "keins erreichbar"}
                  </summary>
                  <div className="table-wrap" style={{ marginTop: 8 }}>
                    <table>
                      <tbody>
                        {members.map((m) => (
                          <tr key={m.id}>
                            <td style={{ width: 1, whiteSpace: "nowrap" }}>
                              <KindIcon kind={m.kind} className="muted" />
                            </td>
                            <td><Link to={`/geraete/${m.id}`}>{m.name}</Link></td>
                            <td className="mono muted">{m.ip || "—"}</td>
                            <td>
                              <span className={`badge ${m.status === "online" ? "ok" : m.status === "offline" ? "danger" : ""}`}>
                                {m.status === "online" ? "erreichbar" : m.status === "offline" ? "nicht erreichbar" : "unbekannt"}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </details>
              );
            })}
          </div>
        )}
      </div>

      <div className="card">
        <div className="row" style={{ justifyContent: "space-between", marginBottom: 10 }}>
          <h2 style={{ margin: 0 }}>Dauerüberwachung</h2>
          {monitor && (
            <span className={`badge ${monitor.enabled && monitor.status.running ? "ok" : "warn"}`}>
              {monitor.enabled
                ? monitor.status.running
                  ? `alle ${monitor.intervalSeconds} s`
                  : "nicht gestartet"
                : "abgeschaltet"}
            </span>
          )}
        </div>

        {!monitor ? (
          <span className="spinner" />
        ) : monitor.systems.length === 0 ? (
          <p className="muted">
            Noch kein Gerät unter Dauerüberwachung. Geräte mit der Bedeutung „kritisch" werden beim
            nächsten Scan automatisch aufgenommen — oder du schaltest sie auf der Geräteseite einzeln
            ein.
          </p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr><th>Gerät</th><th>Adresse</th><th>Geprüft</th><th>Zustand</th><th>Zuletzt erreichbar</th></tr>
              </thead>
              <tbody>
                {monitor.systems.map((s) => (
                  <tr key={s.id}>
                    <td><Link to={`/geraete/${s.id}`}>{s.name}</Link></td>
                    <td className="mono">{s.ip || "—"}</td>
                    <td className="muted mono">
                      {s.ports.length > 0 ? `Port ${s.ports.join(", ")}` : "Ping"}
                    </td>
                    <td>
                      <span className={`badge ${s.status === "online" ? "ok" : s.status === "offline" ? "danger" : ""}`}>
                        {s.status === "online" ? "erreichbar" : s.status === "offline" ? "nicht erreichbar" : "unbekannt"}
                      </span>
                    </td>
                    <td className="muted">
                      {s.lastSeen ? new Date(s.lastSeen).toLocaleString("de-DE") : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {monitor && monitor.events.length > 0 && (
          <>
            <h3 style={{ marginTop: 22 }}>Letzte Zustandswechsel</h3>
            <p className="muted" style={{ marginTop: -8, fontSize: "0.85rem" }}>
              Nur Wechsel werden festgehalten — ein Gerät, das durchgehend läuft, erzeugt keine Einträge.
            </p>
            <div className="table-wrap">
              <table>
                <tbody>
                  {monitor.events.slice(0, 12).map((e) => (
                    <tr key={e.id}>
                      <td style={{ width: 160 }} className="muted">{new Date(e.at).toLocaleString("de-DE")}</td>
                      <td>{e.systemName ?? "unbekanntes Gerät"}</td>
                      <td>
                        <span className={`badge ${e.status === "online" ? "ok" : "danger"}`}>
                          {e.status === "online" ? "wieder da" : "ausgefallen"}
                        </span>
                      </td>
                      <td className="muted">{e.detail}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>

      <div className="card">
        <h2>Namensauflösung (DNS)</h2>
        <p className="muted" style={{ marginTop: -6 }}>
          Prüft, ob Internetadressen in IP-Adressen übersetzt werden. Klemmt das, laden keine
          Webseiten — obwohl die Verbindung selbst in Ordnung ist.
        </p>
        {!dns ? (
          <button onClick={() => void runDns()} disabled={checking !== ""}>
            {checking === "dns" ? "Prüfe…" : "Jetzt testen"}
          </button>
        ) : (
          <>
            <div className={`notice ${dns.resolvedCount === dns.totalCount ? "ok" : "error"}`}>
              {dns.explanation}
            </div>
            <p className="muted">{dns.serversExplanation}</p>
            <div className="table-wrap">
              <table>
                <thead><tr><th>Name</th><th>Ergebnis</th><th>Dauer</th></tr></thead>
                <tbody>
                  {dns.results.map((r) => (
                    <tr key={r.name}>
                      <td className="mono">{r.name}</td>
                      <td>
                        {r.resolved ? (
                          <span className="mono">{r.addresses.join(", ")}</span>
                        ) : (
                          <span className="badge danger">nicht auflösbar</span>
                        )}
                      </td>
                      <td className={r.elapsedMs > 1500 ? "badge warn" : "muted"}>{r.elapsedMs} ms</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>
    </>
  );
}
