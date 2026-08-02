import { useCallback, useEffect, useState } from "react";
import { api, type AccessLogEntry } from "../lib/api";

/** Erklärt jede Aktion in Klartext — ein Protokoll, das nur `secret.reveal` anzeigt, hilft
 *  niemandem, der wissen will, ob jemand an die Passwörter gegangen ist. */
const ACTION_LABEL: Record<string, string> = {
  login: "Anmeldung",
  "login.mfa": "Zwei-Faktor-Abfrage",
  "password.change": "Passwort geändert",
  "mfa.enable": "Zwei-Faktor aktiviert",
  "mfa.disable": "Zwei-Faktor abgeschaltet",
  "user.create": "Benutzer angelegt",
  "user.update": "Benutzer geändert",
  "user.delete": "Benutzer gelöscht",
  "secret.reveal": "Passwort angezeigt",
  "scan.start": "Netzwerk-Scan gestartet",
};

const CRITICAL = new Set(["secret.reveal", "mfa.disable", "user.create", "user.update", "user.delete"]);

export default function AccessLogPage() {
  const [entries, setEntries] = useState<AccessLogEntry[]>([]);
  const [actions, setActions] = useState<string[]>([]);
  const [action, setAction] = useState("");
  const [onlyFailures, setOnlyFailures] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await api.accessLog({ limit: 300, action: action || undefined, onlyFailures });
      setEntries(r.entries);
      setActions(r.actions);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [action, onlyFailures]);

  useEffect(() => {
    void load();
  }, [load]);

  const failures = entries.filter((e) => !e.ok).length;

  return (
    <>
      <div className="page-header">
        <div>
          <h1>Zugriffsprotokoll</h1>
          <p>
            Anmeldungen, Fehlversuche und alles, was an Benutzern oder gespeicherten Passwörtern
            verändert oder angesehen wurde. Die letzten 5000 Einträge bleiben erhalten.
          </p>
        </div>
        <button className="secondary" onClick={() => void load()} disabled={loading}>
          {loading ? "Lade…" : "Aktualisieren"}
        </button>
      </div>

      {error && <div className="notice error">{error}</div>}

      {failures > 0 && !onlyFailures && (
        <div className="notice info">
          {failures} fehlgeschlagene{failures === 1 ? "r Versuch" : " Versuche"} in dieser Ansicht.{" "}
          <button className="secondary small" onClick={() => setOnlyFailures(true)}>Nur diese zeigen</button>
        </div>
      )}

      <div className="card">
        <div className="row" style={{ marginBottom: 14 }}>
          <select style={{ width: "auto" }} value={action} onChange={(e) => setAction(e.target.value)}>
            <option value="">Alle Vorgänge</option>
            {actions.map((a) => (
              <option key={a} value={a}>{ACTION_LABEL[a] ?? a}</option>
            ))}
          </select>
          <label className="row" style={{ cursor: "pointer", fontWeight: 400, color: "var(--text)", margin: 0 }}>
            <input type="checkbox" style={{ width: "auto" }} checked={onlyFailures}
                   onChange={(e) => setOnlyFailures(e.target.checked)} />
            Nur Fehlversuche
          </label>
        </div>

        {loading ? (
          <span className="spinner" />
        ) : entries.length === 0 ? (
          <p className="muted">Keine Einträge für diese Auswahl.</p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr><th>Zeitpunkt</th><th>Vorgang</th><th>Benutzer</th><th>Details</th><th>Herkunft</th></tr>
              </thead>
              <tbody>
                {entries.map((e) => (
                  <tr key={e.id}>
                    <td className="muted" style={{ whiteSpace: "nowrap" }}>
                      {new Date(e.at).toLocaleString("de-DE")}
                    </td>
                    <td>
                      <span className={`badge ${!e.ok ? "danger" : CRITICAL.has(e.action) ? "warn" : ""}`}>
                        {ACTION_LABEL[e.action] ?? e.action}
                      </span>
                    </td>
                    <td>{e.username || <span className="muted">—</span>}</td>
                    <td className="muted">
                      {e.detail || (e.ok ? "" : "fehlgeschlagen")}
                    </td>
                    <td className="muted mono" style={{ fontSize: "0.8rem" }}>
                      {e.ip || "—"}
                      {e.userAgent && (
                        <div title={e.userAgent} style={{ maxWidth: 220, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                          {e.userAgent}
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  );
}
