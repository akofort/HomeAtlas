import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, type Account, type System } from "../lib/api";
import { useAuth } from "../App";
import Markdown from "../components/Markdown";

const KINDS = [
  "router", "network", "server", "nas", "container", "vm", "pc", "mobile", "printer",
  "camera", "smarthome", "climate", "heating", "energy", "media", "iot", "other",
];

export default function SystemDetailPage() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const { isAdmin } = useAuth();
  const [system, setSystem] = useState<System | null>(null);
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [draft, setDraft] = useState<Partial<System>>({});
  const [editing, setEditing] = useState(false);
  const [error, setError] = useState("");
  const [saved, setSaved] = useState(false);
  const [secrets, setSecrets] = useState<Record<string, string>>({});

  useEffect(() => {
    api
      .getSystem(id)
      .then((r) => {
        setSystem(r.system);
        setAccounts(r.accounts);
      })
      .catch((e) => setError(e.message));
  }, [id]);

  async function save() {
    try {
      const { system: updated } = await api.updateSystem(id, draft);
      setSystem(updated);
      setEditing(false);
      setSaved(true);
      setTimeout(() => setSaved(false), 2500);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  async function reveal(accountId: string) {
    try {
      const { secret } = await api.revealSecret(accountId);
      setSecrets((current) => ({ ...current, [accountId]: secret }));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  async function remove() {
    if (!window.confirm(`„${system?.name}" wirklich löschen? Zugehörige Zugänge werden mitgelöscht.`)) return;
    await api.deleteSystem(id);
    navigate("/geraete");
  }

  if (error) return <div className="notice error">{error}</div>;
  if (!system) return <span className="spinner" />;

  const docker = system.extra?.docker;

  return (
    <>
      <div className="page-header">
        <div>
          <Link to="/geraete" className="muted">← Zurück zu allen Geräten</Link>
          <h1 style={{ marginTop: 8 }}>{system.name}</h1>
          <p>{system.purpose || "Kein Zweck hinterlegt."}</p>
          <div className="row">
            <span className={`badge ${system.status === "online" ? "ok" : system.status === "offline" ? "danger" : ""}`}>
              {system.status === "online" ? "erreichbar" : system.status === "offline" ? "nicht erreichbar" : "Zustand unbekannt"}
            </span>
            {system.importance === "critical" && <span className="badge warn">kritisch fürs Haus</span>}
            {system.discovered === 1 && <span className="badge">automatisch gefunden</span>}
            {system.url && (
              <a className="badge" href={system.url} target="_blank" rel="noreferrer">Weboberfläche öffnen ↗</a>
            )}
          </div>
        </div>
        {isAdmin && !editing && (
          <div className="row">
            <button className="secondary" onClick={() => { setDraft(system); setEditing(true); }}>Bearbeiten</button>
            <button className="danger" onClick={() => void remove()}>Löschen</button>
          </div>
        )}
      </div>

      {saved && <div className="notice ok">Gespeichert. Diese Angaben bleiben bei künftigen Scans erhalten.</div>}

      {editing ? (
        <div className="card">
          <h2>Gerät bearbeiten</h2>
          <div className="grid cols-2">
            {([
              ["name", "Name"], ["ip", "Adresse im Netzwerk"], ["hostname", "Hostname"],
              ["vendor", "Hersteller"], ["model", "Modell"], ["location", "Standort"],
              ["url", "Weboberfläche (URL)"], ["purpose", "Zweck in einem Satz"],
            ] as const).map(([field, label]) => (
              <div className="field" key={field}>
                <label>{label}</label>
                <input value={(draft[field] as string) ?? ""}
                       onChange={(e) => setDraft({ ...draft, [field]: e.target.value })} />
              </div>
            ))}
            <div className="field">
              <label>Art des Geräts</label>
              <select value={draft.kind ?? "other"} onChange={(e) => setDraft({ ...draft, kind: e.target.value })}>
                {KINDS.map((k) => <option key={k} value={k}>{k}</option>)}
              </select>
            </div>
            <div className="field">
              <label>Bedeutung</label>
              <select value={draft.importance ?? "normal"}
                      onChange={(e) => setDraft({ ...draft, importance: e.target.value as System["importance"] })}>
                <option value="critical">kritisch — Ausfall fällt im Haus auf</option>
                <option value="normal">normal</option>
                <option value="low">gering</option>
              </select>
            </div>
          </div>
          <div className="field">
            <label>Beschreibung für Laien (Markdown)</label>
            <textarea value={draft.descriptionMd ?? ""}
                      onChange={(e) => setDraft({ ...draft, descriptionMd: e.target.value })} />
          </div>
          <div className="field">
            <label>Interne Notiz</label>
            <input value={draft.notes ?? ""} onChange={(e) => setDraft({ ...draft, notes: e.target.value })} />
          </div>
          <div className="row">
            <button onClick={() => void save()}>Speichern</button>
            <button className="secondary" onClick={() => setEditing(false)}>Abbrechen</button>
          </div>
        </div>
      ) : (
        <div className="grid cols-2">
          <div className="card">
            <h2>Beschreibung</h2>
            {system.descriptionMd ? (
              <Markdown>{system.descriptionMd}</Markdown>
            ) : (
              <p className="muted">Noch keine Beschreibung. Ein Netzwerk-Scan mit KI-Unterstützung ergänzt sie automatisch.</p>
            )}
            {system.notes && <p className="muted" style={{ marginTop: 12 }}><strong>Notiz:</strong> {system.notes}</p>}
          </div>

          <div className="card">
            <h2>Technische Daten</h2>
            <div className="table-wrap">
              <table>
                <tbody>
                  {([
                    ["Adresse im Netzwerk", system.ip], ["Hostname", system.hostname],
                    ["Geräte-Kennung (MAC)", system.mac], ["Hersteller", system.vendor],
                    ["Modell", system.model], ["Standort", system.location],
                    ["Zuletzt gesehen", system.lastSeen ? new Date(system.lastSeen).toLocaleString("de-DE") : ""],
                    ["Erstmals gesehen", system.firstSeen ? new Date(system.firstSeen).toLocaleString("de-DE") : ""],
                    ["Gefunden über", system.discoverySource],
                  ] as const)
                    .filter(([, value]) => value)
                    .map(([label, value]) => (
                      <tr key={label}>
                        <th style={{ width: "45%" }}>{label}</th>
                        <td className="mono">{value}</td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {docker && (
        <div className="card">
          <h2>Container-Details</h2>
          <div className="table-wrap">
            <table>
              <tbody>
                <tr><th>Image</th><td className="mono">{docker.image}</td></tr>
                <tr><th>Zustand</th><td>{docker.status || docker.state}</td></tr>
                {docker.composeProject && <tr><th>Compose-Projekt</th><td className="mono">{docker.composeProject}</td></tr>}
                {docker.portMappings?.length > 0 && (
                  <tr><th>Port-Weiterleitungen</th><td className="mono">{docker.portMappings.join(", ")}</td></tr>
                )}
                {docker.volumes?.length > 0 && (
                  <tr><th>Datenablagen</th><td className="mono">{docker.volumes.join(", ")}</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {(system.services?.length ?? 0) > 0 && (
        <div className="card">
          <h2>Erreichbare Dienste</h2>
          <div className="table-wrap">
            <table>
              <thead><tr><th>Port</th><th>Dienst</th><th>Was das bedeutet</th></tr></thead>
              <tbody>
                {system.services!.map((s) => (
                  <tr key={s.port}>
                    <td className="mono">{s.port}</td>
                    <td>{s.service}</td>
                    <td className="muted">{s.explanation}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {isAdmin && (
        <div className="card">
          <h2>Zugänge</h2>
          {accounts.length === 0 ? (
            <p className="muted">Für dieses Gerät ist kein Zugang hinterlegt.</p>
          ) : (
            <div className="table-wrap">
              <table>
                <thead><tr><th>Bezeichnung</th><th>Benutzername</th><th>Passwort</th></tr></thead>
                <tbody>
                  {accounts.map((a) => (
                    <tr key={a.id}>
                      <td>{a.label}</td>
                      <td className="mono">{a.username || "—"}</td>
                      <td>
                        {!a.hasSecret ? (
                          <span className="muted">kein Passwort hinterlegt</span>
                        ) : secrets[a.id] !== undefined ? (
                          <code className="mono">{secrets[a.id]}</code>
                        ) : (
                          <button className="secondary small" onClick={() => void reveal(a.id)}>Anzeigen</button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </>
  );
}
