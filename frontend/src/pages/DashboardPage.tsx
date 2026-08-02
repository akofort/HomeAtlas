import { useCallback, useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { api, type Dashboard, type DiagnosticResult } from "../lib/api";
import { useAuth } from "../App";

export default function DashboardPage() {
  const { isAdmin } = useAuth();
  const [data, setData] = useState<Dashboard | null>(null);
  const [error, setError] = useState("");
  const [check, setCheck] = useState<DiagnosticResult | null>(null);
  const [checking, setChecking] = useState(false);
  const timer = useRef<number | null>(null);

  const load = useCallback(async () => {
    try {
      setData(await api.dashboard());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  // Refresh at the monitor's own cadence so the important-devices list shows live state rather
  // than whatever it was when the page opened. Paused while the tab is hidden — a background tab
  // polling every ten seconds for hours is pure battery drain.
  useEffect(() => {
    function schedule() {
      if (timer.current) window.clearInterval(timer.current);
      if (document.visibilityState !== "visible" || !data?.monitorEnabled) return;
      const seconds = Math.max(5, data?.monitorIntervalSeconds ?? 10);
      timer.current = window.setInterval(() => void load(), seconds * 1000);
    }
    schedule();
    document.addEventListener("visibilitychange", schedule);
    return () => {
      if (timer.current) window.clearInterval(timer.current);
      document.removeEventListener("visibilitychange", schedule);
    };
  }, [data?.monitorIntervalSeconds, data?.monitorEnabled, load]);

  async function runInternetCheck() {
    setChecking(true);
    setCheck(null);
    try {
      setCheck((await api.runDiagnostic("internet_check")).result);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setChecking(false);
    }
  }

  if (error) return <div className="notice error">{error}</div>;
  if (!data) return <span className="spinner" />;

  const { counts } = data;

  return (
    <>
      <div className="page-header">
        <div>
          <h1>{data.homeName}</h1>
          <p>
            {counts.total === 0
              ? "Noch nichts dokumentiert. Ein Netzwerk-Scan findet die Geräte im Haus automatisch."
              : `${counts.total} Geräte dokumentiert, davon ${counts.online} gerade erreichbar.`}
          </p>
        </div>
        <div className="row">
          <button className="secondary" onClick={() => void runInternetCheck()} disabled={checking}>
            {checking ? "Prüfe…" : "Internet prüfen"}
          </button>
          {isAdmin && <Link className="btn" to="/scan" style={{ display: "inline-block" }}>Netzwerk scannen</Link>}
        </div>
      </div>

      {check && (
        <div className={`notice ${check.internetReachable && check.dnsWorks && check.websitesLoad ? "ok" : "error"}`}>
          {check.explanation}
        </div>
      )}

      {!data.llmConfigured && isAdmin && (
        <div className="notice info">
          Der KI-Assistent ist noch nicht eingerichtet. Unter{" "}
          <Link to="/einstellungen">Einstellungen → KI-Assistent</Link> einen Anbieter wählen — danach
          kann er bei Störungen mitsuchen und die Dokumentation in verständlicher Sprache schreiben.
        </div>
      )}

      <div className="grid cols-4" style={{ marginBottom: 18 }}>
        <div className="stat">
          <div className="stat-value">{counts.total}</div>
          <div className="stat-label">Geräte insgesamt</div>
        </div>
        <div className="stat">
          <div className="stat-value" style={{ color: "var(--ok)" }}>{counts.online}</div>
          <div className="stat-label">gerade erreichbar</div>
        </div>
        <div className="stat">
          <div className="stat-value" style={{ color: counts.critical ? "var(--warn)" : undefined }}>
            {counts.critical}
          </div>
          <div className="stat-label">kritisch fürs Haus</div>
        </div>
        <div className="stat">
          <div className="stat-value">{counts.accounts}</div>
          <div className="stat-label">hinterlegte Zugänge</div>
        </div>
      </div>

      <div className="grid cols-2">
        <div className="card">
          <div className="row" style={{ justifyContent: "space-between", marginBottom: 10 }}>
            <h2 style={{ margin: 0 }}>Wichtigste Geräte</h2>
            {data.monitorEnabled ? (
              <span className="badge ok" title="Diese Geräte werden laufend geprüft">
                live · alle {data.monitorIntervalSeconds} s
              </span>
            ) : (
              <span className="badge warn">Überwachung aus</span>
            )}
          </div>
          {data.criticalSystems.length === 0 ? (
            <p className="muted">
              Noch kein Gerät als kritisch markiert. Geräte, ohne die im Haus etwas ausfällt, lassen
              sich in der Geräteansicht so kennzeichnen — sie werden dann automatisch laufend geprüft.
            </p>
          ) : (
            <div className="table-wrap">
              <table>
                <tbody>
                  {data.criticalSystems.map((s) => (
                    <tr key={s.id}>
                      <td>
                        <Link to={`/geraete/${s.id}`}>{s.name}</Link>
                        <div className="muted mono" style={{ fontSize: "0.8rem" }}>
                          {s.ip || "—"}
                          {s.monitorPortsEffective && s.monitorPortsEffective.length > 0
                            ? ` · Port ${s.monitorPortsEffective.join(", ")}`
                            : " · Ping"}
                        </div>
                      </td>
                      <td style={{ width: 1, whiteSpace: "nowrap" }}>
                        <span className={`badge ${s.status === "online" ? "ok" : s.status === "offline" ? "danger" : ""}`}>
                          {s.status === "online" ? "erreichbar" : s.status === "offline" ? "nicht erreichbar" : "wird geprüft…"}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {!data.monitorEnabled && isAdmin && (
            <p className="field-hint" style={{ marginTop: 10 }}>
              Die Dauerüberwachung ist abgeschaltet — Zustände bleiben auf dem Stand des letzten
              Scans. Einschalten unter <Link to="/einstellungen">Einstellungen → Überwachung</Link>.
            </p>
          )}
        </div>

        <div className="card">
          <h2>Was es im Netz gibt</h2>
          {Object.keys(data.byKind).length === 0 ? (
            <p className="muted">Noch keine Geräte erfasst.</p>
          ) : (
            <div className="table-wrap">
              <table>
                <tbody>
                  {Object.entries(data.byKind)
                    .sort((a, b) => b[1] - a[1])
                    .map(([kind, count]) => (
                      <tr key={kind}>
                        <td>
                          <Link to={`/geraete?kind=${kind}`}>{data.kindLabels[kind] ?? kind}</Link>
                        </td>
                        <td style={{ width: 1, textAlign: "right" }}>{count}</td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </div>
          )}
          {data.lastScan && (
            <p className="muted" style={{ marginTop: 14, marginBottom: 0, fontSize: "0.85rem" }}>
              Letzter Scan: {new Date(data.lastScan.startedAt).toLocaleString("de-DE")} ({data.lastScan.status})
            </p>
          )}
        </div>
      </div>
    </>
  );
}
