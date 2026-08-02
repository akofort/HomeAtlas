import { useCallback, useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { api, type DnsResult, type MonitorState } from "../lib/api";
import { useAuth } from "../App";

/** Netzplan, Live-Überwachung und Diagnose auf einer Seite — die drei Dinge, die man ansieht,
 *  wenn man wissen will, wie es dem Netz gerade geht. */
export default function PlanPage() {
  const { isAdmin } = useAuth();
  const [svg, setSvg] = useState("");
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
    void loadMonitor();
  }, [loadMonitor]);

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
          Von oben nach unten: Internet, Router, Verteilung, Server, Endgeräte. Automatisch aus dem
          erzeugt, was HomeAtlas gefunden hat.
        </p>
        {svg ? (
          <div className="table-wrap" dangerouslySetInnerHTML={{ __html: svg }} />
        ) : (
          <span className="spinner" />
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
