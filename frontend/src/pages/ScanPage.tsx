import { useCallback, useEffect, useRef, useState } from "react";
import { api, type Scan } from "../lib/api";

export default function ScanPage() {
  const [scan, setScan] = useState<Scan | null>(null);
  const [history, setHistory] = useState<Scan[]>([]);
  const [error, setError] = useState("");
  const [starting, setStarting] = useState(false);
  const timer = useRef<number | null>(null);

  const load = useCallback(async () => {
    try {
      const { scans, running } = await api.listScans();
      setHistory(scans);
      // Prefer the running scan; otherwise show the most recent finished one.
      const active = running ?? (scans.length > 0 ? await api.getScan(scans[0].id).then((r) => r.scan) : null);
      setScan(active);
      return active;
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return null;
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  // Poll only while a scan is running -- a finished scan is a static row, and polling it forever
  // would keep the tab busy for nothing.
  useEffect(() => {
    if (scan?.status !== "running") {
      if (timer.current) window.clearInterval(timer.current);
      return;
    }
    timer.current = window.setInterval(() => {
      void api.getScan(scan.id).then((r) => {
        setScan(r.scan);
        if (r.scan.status !== "running") void load();
      });
    }, 1500);
    return () => {
      if (timer.current) window.clearInterval(timer.current);
    };
  }, [scan?.id, scan?.status, load]);

  async function start() {
    setStarting(true);
    setError("");
    try {
      const { scanId } = await api.startScan();
      setScan((await api.getScan(scanId)).scan);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setStarting(false);
    }
  }

  const running = scan?.status === "running";
  const summary = scan?.summary;
  const warnings: string[] = summary?.warnings ?? [];

  return (
    <>
      <div className="page-header">
        <div>
          <h1>Netzwerk-Scan</h1>
          <p>
            HomeAtlas sucht die Geräte im Heimnetz, erkennt ihre Dienste, fragt Docker ab und schreibt
            anschließend die Dokumentation neu. Ein Durchlauf dauert je nach Netzgröße einige Minuten.
          </p>
        </div>
        <button onClick={() => void start()} disabled={starting || running}>
          {running ? "Scan läuft…" : starting ? "Starte…" : "Scan starten"}
        </button>
      </div>

      {error && <div className="notice error">{error}</div>}

      {scan && (
        <div className="card">
          <div className="row" style={{ justifyContent: "space-between", marginBottom: 12 }}>
            <h2 style={{ margin: 0 }}>
              {running ? scan.phase || "Läuft…" : scan.status === "completed" ? "Abgeschlossen" : "Fehlgeschlagen"}
            </h2>
            <span className={`badge ${scan.status === "completed" ? "ok" : scan.status === "failed" ? "danger" : ""}`}>
              {new Date(scan.startedAt).toLocaleString("de-DE")}
            </span>
          </div>

          <div className="progress"><div style={{ width: `${scan.progress}%` }} /></div>

          {summary && (
            <div className="grid cols-4" style={{ marginTop: 18 }}>
              <div className="stat">
                <div className="stat-value">{summary.devicesFound ?? 0}</div>
                <div className="stat-label">Geräte gefunden</div>
              </div>
              <div className="stat">
                <div className="stat-value" style={{ color: "var(--ok)" }}>{summary.created ?? 0}</div>
                <div className="stat-label">neu hinzugekommen</div>
              </div>
              <div className="stat">
                <div className="stat-value">{summary.updated ?? 0}</div>
                <div className="stat-label">aktualisiert</div>
              </div>
              <div className="stat">
                <div className="stat-value">{summary.gateway || "—"}</div>
                <div className="stat-label">Router</div>
              </div>
            </div>
          )}

          {warnings.length > 0 && (
            <div className="notice info" style={{ marginTop: 16 }}>
              <strong>Hinweise:</strong>
              <ul style={{ margin: "6px 0 0", paddingLeft: "1.2em" }}>
                {warnings.map((w, i) => <li key={i}>{w}</li>)}
              </ul>
            </div>
          )}

          {summary?.error && <div className="notice error" style={{ marginTop: 16 }}>{summary.error}</div>}

          {scan.log && (
            <details style={{ marginTop: 16 }}>
              <summary className="muted" style={{ cursor: "pointer" }}>Ausführliches Protokoll</summary>
              <pre className="mono" style={{
                background: "var(--bg)", padding: 14, borderRadius: 9,
                overflowX: "auto", maxHeight: 320, fontSize: "0.8rem",
              }}>{scan.log}</pre>
            </details>
          )}
        </div>
      )}

      {history.length > 1 && (
        <div className="card">
          <h2>Frühere Scans</h2>
          <div className="table-wrap">
            <table>
              <thead><tr><th>Zeitpunkt</th><th>Bereich</th><th>Ergebnis</th><th>Status</th></tr></thead>
              <tbody>
                {history.map((s) => (
                  <tr key={s.id}>
                    <td>{new Date(s.startedAt).toLocaleString("de-DE")}</td>
                    <td className="mono">{s.subnets}</td>
                    <td>{s.summary?.devicesFound != null ? `${s.summary.devicesFound} Geräte` : "—"}</td>
                    <td>
                      <span className={`badge ${s.status === "completed" ? "ok" : s.status === "failed" ? "danger" : ""}`}>
                        {s.status === "completed" ? "fertig" : s.status === "failed" ? "fehlgeschlagen" : "läuft"}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </>
  );
}
