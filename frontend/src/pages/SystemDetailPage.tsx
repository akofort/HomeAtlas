import { useEffect, useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  api, type Account, type ConfigVersion, type DeviceErrorEvent, type ProbeResult,
  type RemoteContainer, type System,
} from "../lib/api";
import { useAuth } from "../App";
import Markdown from "../components/Markdown";
import { KindIcon } from "../lib/icons";
import Terminal from "../components/Terminal";

/** Same eligibility test as backend/app/main.py's `_ssh_eligible` / probe_auth's SSH branch --
 *  keep these in sync. */
function sshEligible(a: Account): boolean {
  const port = a.port || 0;
  return a.category === "sshkey" || (a.category === "login" && (port === 0 || port === 22));
}

const KINDS = [
  "router", "network", "server", "nas", "container", "vm", "pc", "mobile", "printer",
  "camera", "smarthome", "climate", "heating", "energy", "media", "iot", "other",
];

export default function SystemDetailPage() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const { isAdmin } = useAuth();
  const [system, setSystem] = useState<System | null>(null);
  const [derived, setDerived] = useState("");
  const [monitorPorts, setMonitorPorts] = useState<number[]>([]);
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [draft, setDraft] = useState<Partial<System>>({});
  const [editing, setEditing] = useState(false);
  const [error, setError] = useState("");
  const [saved, setSaved] = useState(false);
  const [secrets, setSecrets] = useState<Record<string, string>>({});
  const [probing, setProbing] = useState(false);
  const [probeNotice, setProbeNotice] = useState<{ kind: "ok" | "error" | "info"; text: string } | null>(null);
  const [configVersions, setConfigVersions] = useState<ConfigVersion[] | null>(null);
  const [configPreview, setConfigPreview] = useState<ConfigVersion | null>(null);
  const [errorEvents, setErrorEvents] = useState<DeviceErrorEvent[] | null>(null);
  const [showErrorLog, setShowErrorLog] = useState(false);
  const [consoleAccountId, setConsoleAccountId] = useState<string | null>(null);
  const [keyGenBusy, setKeyGenBusy] = useState(false);
  const [keyGenNotice, setKeyGenNotice] = useState<{ kind: "ok" | "error"; text: string } | null>(null);
  const [containerBusy, setContainerBusy] = useState("");
  const [containerNotice, setContainerNotice] = useState<{ kind: "ok" | "error"; text: string } | null>(null);
  const [showLogs, setShowLogs] = useState(false);
  const [logLines, setLogLines] = useState("");
  const [showDockerConsole, setShowDockerConsole] = useState(false);
  const logsAbortRef = useRef<AbortController | null>(null);

  useEffect(() => {
    api
      .getSystem(id)
      .then((r) => {
        setSystem(r.system);
        setAccounts(r.accounts);
        setDerived(r.description);
        setMonitorPorts(r.monitorPortsEffective);
        // Config backups only exist for routers/switches -- no point asking for anything else.
        if (r.system.kind === "router" || r.system.kind === "network") {
          api.listConfigVersions(id).then((cv) => setConfigVersions(cv.versions)).catch(() => setConfigVersions([]));
        }
        // Fetched for every device, unlike config backups -- any device can accumulate a probe
        // failure or a monitoring-down event, and the warning badge needs a real count to show.
        api.listSystemErrors(id).then((r2) => setErrorEvents(r2.events)).catch(() => setErrorEvents([]));
      })
      .catch((e) => setError(e.message));
  }, [id]);

  async function showConfigVersion(version: ConfigVersion) {
    if (configPreview?.id === version.id) {
      setConfigPreview(null);
      return;
    }
    try {
      setConfigPreview((await api.getConfigVersion(id, version.id)).version);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  async function downloadConfigVersion(version: ConfigVersion) {
    try {
      const full = (await api.getConfigVersion(id, version.id)).version;
      const content = full.content ?? "";
      // Binary backups (e.g. an Omada Controller export) are stored as one unbroken Base64
      // string -- everything else here is multi-line device config text, which no real Base64
      // payload looks like, so this is a safe way to tell the two apart without a dedicated flag.
      const isBase64 = content.length % 4 === 0 && /^[A-Za-z0-9+/]+=*$/.test(content);
      const blob = isBase64
        ? new Blob([Uint8Array.from(atob(content), (c) => c.charCodeAt(0))], { type: "application/octet-stream" })
        : new Blob([content], { type: "text/plain" });
      const safeName = full.label.replace(/[^\w.-]+/g, "_");
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${safeName}.${isBase64 ? "cfg" : "txt"}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

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

  async function probe() {
    setProbing(true);
    setProbeNotice(null);
    try {
      const { outcome, system: updated } = await api.probeSystem(id);
      setSystem(updated);
      if (updated.kind === "router" || updated.kind === "network") {
        void api.listConfigVersions(id).then((cv) => setConfigVersions(cv.versions));
      }
      if (outcome.ran) {
        setProbeNotice({ kind: "ok", text: `Gerät ausgelesen über: ${Object.keys(outcome.results).join(", ")}` });
      } else {
        const reasons = Object.values(outcome.results).map((r) => r.error).filter(Boolean);
        setProbeNotice({
          kind: "error",
          text: reasons.length > 0 ? reasons.join(" · ") : outcome.reason || "Keine Verbindung möglich.",
        });
      }
    } catch (e) {
      setProbeNotice({ kind: "error", text: e instanceof Error ? e.message : String(e) });
    } finally {
      setProbing(false);
    }
  }

  async function remove() {
    if (!window.confirm(`„${system?.name}" wirklich löschen? Zugehörige Zugänge werden mitgelöscht.`)) return;
    await api.deleteSystem(id);
    navigate("/geraete");
  }

  async function runContainerAction(action: "start" | "stop" | "restart") {
    if (action !== "start" && !window.confirm(
      `Container wirklich ${action === "stop" ? "stoppen" : "neu starten"}? Der darauf laufende Dienst ist währenddessen nicht erreichbar.`,
    )) return;
    setContainerBusy(action);
    setContainerNotice(null);
    try {
      if (action === "start") await api.startContainer(id);
      else if (action === "stop") await api.stopContainer(id);
      else await api.restartContainer(id);
      const labels = { start: "gestartet", stop: "gestoppt", restart: "neu gestartet" } as const;
      setContainerNotice({ kind: "ok", text: `Container ${labels[action]}.` });
      const { system: updated } = await api.getSystem(id);
      setSystem(updated);
    } catch (e) {
      setContainerNotice({ kind: "error", text: e instanceof Error ? e.message : String(e) });
    } finally {
      setContainerBusy("");
    }
  }

  async function startLogs() {
    setShowLogs(true);
    setLogLines("");
    const controller = new AbortController();
    logsAbortRef.current = controller;
    try {
      const response = await fetch(api.containerLogsUrl(id), { credentials: "same-origin", signal: controller.signal });
      const reader = response.body?.getReader();
      if (!reader) return;
      const decoder = new TextDecoder();
      // Bounded: an unattended live tail left open for hours must not grow the tab's memory
      // without limit -- keep only the most recent slice, same spirit as the backend's own
      // truncation of tool results and probe facts.
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        setLogLines((current) => (current + decoder.decode(value, { stream: true })).slice(-20000));
      }
    } catch {
      /* aborted by stopLogs(), or the connection dropped -- either way nothing to report */
    }
  }

  function stopLogs() {
    logsAbortRef.current?.abort();
    setShowLogs(false);
  }

  async function generateKeyForThisDevice() {
    setKeyGenBusy(true);
    setKeyGenNotice(null);
    try {
      const { publicKey } = await api.generateSshKey(id, `SSH-Schlüssel (${system?.name ?? "HomeAtlas"})`);
      const r = await api.getSystem(id);
      setAccounts(r.accounts);
      setKeyGenNotice({ kind: "ok", text: `Schlüssel erzeugt. Öffentlicher Teil: ${publicKey}` });
    } catch (e) {
      setKeyGenNotice({ kind: "error", text: e instanceof Error ? e.message : String(e) });
    } finally {
      setKeyGenBusy(false);
    }
  }

  if (error) return <div className="notice error">{error}</div>;
  if (!system) return <span className="spinner" />;

  const docker = system.extra?.docker;
  const probeResults = Object.entries((system.extra?.probe ?? {}) as Record<string, ProbeResult>);
  // Populated by pipeline.py after a scan with a Home Assistant credential -- see
  // probe_auth.extract_printer_supplies / pipeline._apply_printer_supplies.
  const printerSupplies = (system.extra?.printerSupplies ?? []) as { name: string; percent: number }[];
  // Populated by pipeline.py after a scan with an AdGuard Home credential attached to this system
  // -- see adguard_probe.probe / pipeline.py's "AdGuard Home erfassen" step.
  const adguard = system.extra?.adguard as {
    protectionEnabled?: boolean; queries?: number; blocked?: number; blockedPercent?: number;
  } | undefined;
  // SSH console/remote-container actions require an account directly attached via systemId --
  // the backend's _remote_host_and_account/_proxmox_account only ever look at that field, so a
  // group-assigned account (viaAssignment) can be shown in the Zugänge table but can't drive them.
  const directAccounts = accounts.filter((a) => !a.viaAssignment);

  return (
    <>
      <div className="page-header">
        <div>
          <Link to="/geraete" className="muted">← Zurück zu allen Geräten</Link>
          <h1 className="row" style={{ gap: 10, marginTop: 8 }}>
            <KindIcon kind={system.kind} size={24} />
            {system.name}
          </h1>
          <p>{system.purpose || "Kein Zweck hinterlegt."}</p>
          <div className="row">
            <span className={`badge ${system.status === "online" ? "ok" : system.status === "offline" ? "danger" : ""}`}>
              {system.status === "online" ? "erreichbar" : system.status === "offline" ? "nicht erreichbar" : "Zustand unbekannt"}
            </span>
            {system.importance === "critical" && <span className="badge warn">kritisch fürs Haus</span>}
            {!!errorEvents?.length && (
              <button className="badge danger" style={{ cursor: "pointer", border: "none" }}
                      onClick={() => setShowErrorLog((v) => !v)}>
                ⚠ {errorEvents.length} Fehler protokolliert
              </button>
            )}
            {(system.tags ?? []).some((t) => t.toLowerCase().includes("poe")) && (
              <span className="badge warn" title="Funktioniert ohne PoE-fähigen Switch oder Injector nicht">
                ⚡ benötigt PoE
              </span>
            )}
            {system.monitored === 1 && (
              <span className="badge" title={monitorPorts.length > 0 ? `Geprüft wird Port ${monitorPorts.join(", ")}` : "Geprüft wird per Ping"}>
                überwacht · {monitorPorts.length > 0 ? `Port ${monitorPorts.join(", ")}` : "Ping"}
              </span>
            )}
            {system.discovered === 1 && <span className="badge">automatisch gefunden</span>}
            {system.url && (
              <a className="badge" href={system.url} target="_blank" rel="noreferrer">Weboberfläche öffnen ↗</a>
            )}
            {system.docUrl && (
              <a className="badge" href={system.docUrl} target="_blank" rel="noreferrer">
                Hersteller-Dokumentation ↗
              </a>
            )}
            {system.docLink && (
              <a className="badge" href={system.docLink} target="_blank" rel="noreferrer">
                Eigene Dokumentation ↗
              </a>
            )}
          </div>
        </div>
        {isAdmin && !editing && (
          <div className="row">
            {accounts.some((a) => a.allowProbe) && (
              <button className="secondary" onClick={() => void probe()} disabled={probing}>
                {probing ? "Frage ab…" : "Gerät auslesen"}
              </button>
            )}
            <button className="secondary" onClick={() => { setDraft(system); setEditing(true); }}>Bearbeiten</button>
            <button className="danger" onClick={() => void remove()}>Löschen</button>
          </div>
        )}
      </div>

      {probeNotice && <div className={`notice ${probeNotice.kind}`}>{probeNotice.text}</div>}

      {saved && <div className="notice ok">Gespeichert. Diese Angaben bleiben bei künftigen Scans erhalten.</div>}

      {editing ? (
        <div className="card">
          <h2>Gerät bearbeiten</h2>
          <div className="grid cols-2">
            {([
              ["name", "Name"], ["ip", "Adresse im Netzwerk"], ["hostname", "Hostname"],
              ["vendor", "Hersteller"], ["model", "Modell"], ["location", "Standort"],
              ["url", "Weboberfläche (URL)"], ["docUrl", "Hersteller-Dokumentation (URL)"],
              ["docLink", "Eigene Dokumentation (URL)"], ["purpose", "Zweck in einem Satz"],
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
          <div className="field">
            <label>Schlagworte</label>
            <input
              placeholder="z. B. PoE, Dachboden"
              value={(draft.tags ?? []).join(", ")}
              onChange={(e) => setDraft({ ...draft, tags: e.target.value.split(",").map((s) => s.trim()).filter(Boolean) })}
            />
            <div className="field-hint">
              Frei wählbar. Ein Schlagwort mit „PoE" markiert das Gerät als PoE-abhängig — es
              funktioniert dann nur an einem PoE-fähigen Switch oder mit einem Injector, was als
              Hinweis oben und im Geräte-Überblick angezeigt wird.
            </div>
          </div>

          <label className="row" style={{ cursor: "pointer", fontWeight: 400, color: "var(--text)", marginBottom: 8 }}>
            <input type="checkbox" style={{ width: "auto" }} checked={Boolean(draft.monitored)}
                   onChange={(e) => setDraft({ ...draft, monitored: e.target.checked ? 1 : 0 })} />
            Dauerhaft überwachen (alle paar Sekunden prüfen)
          </label>
          {Boolean(draft.monitored) && (
            <div className="field">
              <label>Zu prüfende Ports (optional, max. 3)</label>
              <input
                placeholder="z. B. 443, 445 — leer = automatisch bzw. Ping"
                value={(draft.monitorPorts ?? []).join(", ")}
                onChange={(e) =>
                  setDraft({
                    ...draft,
                    monitorPorts: e.target.value
                      .split(",")
                      .map((s) => Number(s.trim()))
                      .filter((n) => Number.isInteger(n) && n > 0 && n < 65536)
                      .slice(0, 3),
                  })
                }
              />
              <div className="field-hint">
                Ein geprüfter Port sagt mehr als ein Ping: ein NAS, das auf Ping antwortet, während
                die Dateifreigabe tot ist, gilt sonst als „erreichbar".
              </div>
            </div>
          )}
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
            ) : derived ? (
              <>
                <Markdown>{derived}</Markdown>
                <p className="field-hint" style={{ marginTop: 10 }}>
                  Aus Gerätetyp und gefundenen Diensten abgeleitet. Über „Bearbeiten" lässt sich eine
                  eigene Beschreibung hinterlegen, die dann Vorrang hat.
                </p>
              </>
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

      {system.kind === "printer" && printerSupplies.length > 0 && (
        <div className="card">
          <h2>Verbrauchsmaterial</h2>
          <p className="muted" style={{ marginTop: -6 }}>
            Über Home Assistant ausgelesen — Stand vom letzten Netzwerk-Scan.
          </p>
          {printerSupplies.map((supply) => (
            <div key={supply.name} style={{ marginBottom: 12 }}>
              <div className="row" style={{ justifyContent: "space-between", marginBottom: 4 }}>
                <span>{supply.name}</span>
                <span className="muted mono">{Math.round(supply.percent)}%</span>
              </div>
              <div className="progress">
                <div style={{
                  width: `${Math.max(0, Math.min(100, supply.percent))}%`,
                  background: supply.percent <= 15 ? "var(--danger, #ef4444)" : undefined,
                }} />
              </div>
            </div>
          ))}
        </div>
      )}

      {adguard && (
        <div className="card">
          <h2>AdGuard Home</h2>
          <p className="muted" style={{ marginTop: -6 }}>
            DNS-Filterung -- Stand vom letzten Netzwerk-Scan.
          </p>
          <div className="table-wrap">
            <table>
              <tbody>
                <tr>
                  <th style={{ width: "45%" }}>Schutz</th>
                  <td>
                    <span className={`badge ${adguard.protectionEnabled ? "ok" : "danger"}`}>
                      {adguard.protectionEnabled ? "aktiv" : "deaktiviert"}
                    </span>
                  </td>
                </tr>
                {adguard.queries !== undefined && (
                  <tr><th>DNS-Anfragen</th><td className="mono">{adguard.queries.toLocaleString("de-DE")}</td></tr>
                )}
                {adguard.blocked !== undefined && (
                  <tr>
                    <th>Blockiert</th>
                    <td className="mono">
                      {adguard.blocked.toLocaleString("de-DE")}
                      {adguard.blockedPercent !== undefined ? ` (${adguard.blockedPercent}%)` : ""}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
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

          {isAdmin && (
            docker.containerId ? (
              <>
                {containerNotice && <div className={`notice ${containerNotice.kind}`}>{containerNotice.text}</div>}
                <div className="row" style={{ marginTop: 12 }}>
                  <button className="secondary" disabled={containerBusy !== ""} onClick={() => void runContainerAction("start")}>
                    {containerBusy === "start" ? "Starte…" : "Starten"}
                  </button>
                  <button className="secondary" disabled={containerBusy !== ""} onClick={() => void runContainerAction("stop")}>
                    {containerBusy === "stop" ? "Stoppe…" : "Stoppen"}
                  </button>
                  <button className="secondary" disabled={containerBusy !== ""} onClick={() => void runContainerAction("restart")}>
                    {containerBusy === "restart" ? "Starte neu…" : "Neu starten"}
                  </button>
                  {!showLogs ? (
                    <button className="secondary" onClick={() => void startLogs()}>Live-Logs</button>
                  ) : (
                    <button className="secondary" onClick={stopLogs}>Logs schließen</button>
                  )}
                  <button className="secondary" onClick={() => setShowDockerConsole((v) => !v)}>
                    {showDockerConsole ? "Konsole schließen" : "Konsole öffnen"}
                  </button>
                </div>
                {showLogs && (
                  <pre className="mono" style={{
                    marginTop: 12, maxHeight: 320, overflow: "auto", background: "#0b1120",
                    color: "#d7dee8", padding: 12, borderRadius: 10, whiteSpace: "pre-wrap",
                  }}>
                    {logLines || "Warte auf Ausgabe…"}
                  </pre>
                )}
                {showDockerConsole && (
                  <div style={{ marginTop: 12 }}>
                    <Terminal wsUrl={api.dockerConsoleWsUrl(id)} onClose={() => setShowDockerConsole(false)} />
                  </div>
                )}
              </>
            ) : (
              <p className="muted" style={{ marginTop: 12, marginBottom: 0 }}>
                Steuerung braucht die Container-ID aus einem neueren Scan — bitte einmal erneut scannen.
              </p>
            )
          )}
        </div>
      )}

      {probeResults.length > 0 && (
        <div className="card">
          <h2>Direkt vom Gerät ausgelesen</h2>
          <p className="muted" style={{ marginTop: -6 }}>
            Über einen hinterlegten Zugang angemeldet und nur gelesen — nichts wurde verändert.
          </p>
          {probeResults.map(([source, result]) => (
            <div key={source} style={{ marginBottom: 18 }}>
              <div className="row" style={{ marginBottom: 8 }}>
                <span className={`badge ${result.ok ? "ok" : "danger"}`}>{source}</span>
              </div>
              {result.ok ? (
                <div className="table-wrap">
                  <table>
                    <tbody>
                      {Object.entries(result.facts).map(([key, fact]) => (
                        <tr key={key}>
                          <th style={{ width: "28%" }}>{fact.label}</th>
                          <td>
                            {fact.value.includes("\n") ? (
                              <details>
                                <summary className="muted" style={{ cursor: "pointer" }}>
                                  {fact.value.split("\n").length} Zeilen — anzeigen
                                </summary>
                                <pre className="mono" style={{ margin: "8px 0 0", whiteSpace: "pre-wrap", fontSize: "0.82rem" }}>
                                  {fact.value}
                                </pre>
                              </details>
                            ) : (
                              <span className="mono">{fact.value}</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p className="muted">{result.error}</p>
              )}
            </div>
          ))}
        </div>
      )}

      {showErrorLog && !!errorEvents?.length && (
        <div className="card">
          <div className="row" style={{ justifyContent: "space-between", marginBottom: 4 }}>
            <h2 style={{ margin: 0 }}>Fehlerprotokoll</h2>
            <button className="secondary" onClick={() => setShowErrorLog(false)}>Einklappen</button>
          </div>
          <p className="muted" style={{ marginTop: -2 }}>
            Was beim automatischen Auslesen oder bei der Dauerüberwachung an diesem Gerät
            fehlgeschlagen ist — SSH-Zeitüberschreitungen, abgelehnte Zugangsdaten, Ausfälle. Zeigt
            die letzten {errorEvents.length} Einträge.
          </p>
          <div className="table-wrap">
            <table>
              <thead>
                <tr><th>Zeitpunkt</th><th>Stufe</th><th>Meldung</th></tr>
              </thead>
              <tbody>
                {errorEvents.map((ev) => (
                  <tr key={ev.id}>
                    <td className="muted" style={{ whiteSpace: "nowrap" }}>
                      {new Date(ev.createdAt).toLocaleString("de-DE")}
                    </td>
                    <td>
                      <span className={`badge ${ev.level === "error" ? "danger" : ev.level === "warning" ? "warn" : ""}`}>
                        {ev.level}
                      </span>
                    </td>
                    <td>{ev.message}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {configVersions !== null && (system.kind === "router" || system.kind === "network") && (
        <div className="card">
          <h2>Konfigurationsverlauf</h2>
          <p className="muted" style={{ marginTop: -6 }}>
            Textkonfigurationen, die beim Auslesen des Geräts gesichert wurden — nur zum
            Nachsehen, wird nie automatisch auf das Gerät zurückgeschrieben. Kann Zugangsdaten wie
            Community-Strings enthalten, deshalb verschlüsselt gespeichert.
          </p>
          {configVersions.length === 0 ? (
            <p className="muted" style={{ marginBottom: 0 }}>Noch keine Sicherung vorhanden.</p>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr><th>Zeitpunkt</th><th>Bezeichnung</th><th>Quelle</th><th>Umfang</th><th /></tr>
                </thead>
                <tbody>
                  {configVersions.map((v) => (
                    <tr key={v.id}>
                      <td className="muted">{new Date(v.createdAt).toLocaleString("de-DE")}</td>
                      <td>{v.label}</td>
                      <td className="muted">{v.source}</td>
                      <td className="muted">{Math.round(v.size / 100) / 10} kB</td>
                      <td style={{ whiteSpace: "nowrap", width: 1 }}>
                        <button className="secondary" onClick={() => void showConfigVersion(v)}>
                          {configPreview?.id === v.id ? "Einklappen" : "Ansehen"}
                        </button>{" "}
                        <button className="secondary" onClick={() => void downloadConfigVersion(v)}>
                          Herunterladen
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {configPreview && (
            <div style={{ marginTop: 12 }}>
              <div style={{ display: "flex", justifyContent: "flex-end" }}>
                <button className="secondary" onClick={() => setConfigPreview(null)}>Einklappen</button>
              </div>
              <pre className="mono" style={{ marginTop: 4, whiteSpace: "pre-wrap", fontSize: "0.82rem" }}>
                {configPreview.content}
              </pre>
            </div>
          )}
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
          <div className="row" style={{ justifyContent: "space-between", marginBottom: 12 }}>
            <h2 style={{ margin: 0 }}>Zugänge</h2>
            <div className="row" style={{ flexWrap: "nowrap" }}>
              <button className="secondary small" disabled={keyGenBusy} onClick={() => void generateKeyForThisDevice()}>
                {keyGenBusy ? "Erzeuge…" : "SSH-Schlüssel erzeugen"}
              </button>
              <Link className="btn" to="/zugaenge" style={{ display: "inline-block", fontSize: "0.85rem", padding: "5px 11px" }}>
                Zugänge verwalten
              </Link>
            </div>
          </div>
          {keyGenNotice && <div className={`notice ${keyGenNotice.kind}`}>{keyGenNotice.text}</div>}
          {accounts.length === 0 ? (
            <p className="muted">
              Für dieses Gerät ist kein Zugang hinterlegt — unter <Link to="/zugaenge">Zugänge</Link> lässt
              sich einer anlegen und diesem Gerät zuordnen.
            </p>
          ) : (
            <div className="table-wrap">
              <table>
                <thead><tr><th>Bezeichnung</th><th>Benutzername</th><th>Passwort</th><th /></tr></thead>
                <tbody>
                  {accounts.map((a) => (
                    <tr key={a.id}>
                      <td>
                        {a.label}
                        {a.viaAssignment && (
                          <span
                            className="badge"
                            style={{ marginLeft: 6 }}
                            title="Nicht direkt diesem Gerät zugeordnet, sondern über eine Regel (Gerätekategorie/Subnetz/weiteres Gerät) auf der Zugänge-Seite"
                          >
                            über Zuordnung
                          </span>
                        )}
                      </td>
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
                      <td style={{ width: 1, whiteSpace: "nowrap" }}>
                        {/* SSH console/remote actions only work for accounts directly attached via
                         *  systemId -- the backend's _remote_host_and_account requires an exact
                         *  match, so a group-assigned account (viaAssignment) can't use them here;
                         *  it's still visible in the table above, just without these buttons. */}
                        {sshEligible(a) && !a.viaAssignment && (
                          <button className="secondary small" onClick={() => setConsoleAccountId(a.id)}>
                            Konsole öffnen
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {consoleAccountId && (
            <div style={{ marginTop: 16 }}>
              <Terminal
                wsUrl={api.sshConsoleWsUrl(id, consoleAccountId)}
                onClose={() => setConsoleAccountId(null)}
              />
            </div>
          )}
        </div>
      )}

      {/* Same direct-attachment requirement as the console button above -- the backend's
       *  _proxmox_account/_remote_host_and_account only ever look at accounts.systemId, so a
       *  group-assigned account can't drive this card either. */}
      {isAdmin && (directAccounts.some(sshEligible) || directAccounts.some((a) => a.category === "proxmox")) && (
        <RemoteContainersCard
          systemId={id}
          sshAccounts={directAccounts.filter(sshEligible)}
          isProxmoxHost={directAccounts.some((a) => a.category === "proxmox")}
        />
      )}
    </>
  );
}

/** Docker containers (or, on a Proxmox host, its VMs/LXC containers) on a host reached over
 *  SSH/API -- for a host system (server/NAS/Proxmox-node/etc.) that isn't itself modeled as a
 *  container, unlike the local "Container-Details" card above. Needs an explicit "Laden" click
 *  rather than fetching on mount: unlike everything else on this page, listing here means either
 *  opening a real SSH connection to the device or calling its own management API.
 *
 *  A Proxmox host never runs a `docker` command -- it has no Docker CLI at all ("bash: line 1:
 *  docker: command not found" is the bug this branch exists to fix). `isProxmoxHost` (a
 *  "proxmox"-category account is attached to this system, same signal AccountsPage.tsx tells
 *  people to set up) switches the whole card to the read-only VM/LXC view, backed by
 *  proxmox_probe.list_guests (REST, no SSH account needed at all) with `pct list`/`qm list` over
 *  SSH as main.py's own fallback -- see its `list_remote_containers` route. Start/stop/console
 *  controls are Docker-specific and hidden here; VMs/LXC are managed through Proxmox itself. */
function RemoteContainersCard(
  { systemId, sshAccounts, isProxmoxHost }: { systemId: string; sshAccounts: Account[]; isProxmoxHost: boolean },
) {
  const [accountId, setAccountId] = useState(sshAccounts[0]?.id ?? "");
  const [containers, setContainers] = useState<RemoteContainer[] | null>(null);
  const [busyId, setBusyId] = useState("");
  const [consoleContainerId, setConsoleContainerId] = useState<string | null>(null);
  const [notice, setNotice] = useState<{ kind: "ok" | "error"; text: string } | null>(null);
  const [loading, setLoading] = useState(false);

  async function load() {
    setLoading(true);
    setNotice(null);
    try {
      const r = await api.listRemoteContainers(systemId, accountId);
      setContainers(r.containers);
    } catch (e) {
      setNotice({ kind: "error", text: e instanceof Error ? e.message : String(e) });
      setContainers(null);
    } finally {
      setLoading(false);
    }
  }

  async function runAction(containerId: string, action: "start" | "stop" | "restart") {
    if (action !== "start" && !window.confirm(
      `Container wirklich ${action === "stop" ? "stoppen" : "neu starten"}?`,
    )) return;
    setBusyId(containerId + action);
    setNotice(null);
    try {
      await api.remoteContainerAction(systemId, containerId, action, accountId);
      await load();
    } catch (e) {
      setNotice({ kind: "error", text: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusyId("");
    }
  }

  return (
    <div className="card">
      <h2>{isProxmoxHost ? "VMs & LXC-Container auf diesem Proxmox-Host" : "Container auf diesem Host"}</h2>
      <p className="muted" style={{ marginTop: -6 }}>
        {isProxmoxHost ? (
          <>
            Über die Proxmox-API abgefragt (mit „pct list“/„qm list“ per SSH als Ausweichmöglichkeit,
            falls der API-Zugang fehlschlägt) — nur lesend. Gesteuert werden VMs/LXC-Container über
            Proxmox selbst, nicht über HomeAtlas.
          </>
        ) : (
          <>
            Über SSH mit einem der unten hinterlegten Zugänge abgefragt und gesteuert — für
            Docker-Hosts, die nicht selbst als Container in HomeAtlas geführt werden (z. B. ein
            Server-Host mit mehreren Containern).
          </>
        )}
      </p>
      <div className="row" style={{ marginBottom: 12 }}>
        {!isProxmoxHost && sshAccounts.length > 1 && (
          <select style={{ width: "auto" }} value={accountId} onChange={(e) => setAccountId(e.target.value)}>
            {sshAccounts.map((a) => <option key={a.id} value={a.id}>{a.label}</option>)}
          </select>
        )}
        <button className="secondary" onClick={() => void load()}
                disabled={loading || (!isProxmoxHost && !accountId)}>
          {loading ? "Lade…" : containers === null ? "Laden" : "Neu laden"}
        </button>
      </div>

      {notice && <div className={`notice ${notice.kind}`}>{notice.text}</div>}

      {containers !== null && (
        containers.length === 0 ? (
          <p className="muted">
            {isProxmoxHost ? "Keine VMs/LXC-Container auf diesem Host gefunden." : "Keine Container auf diesem Host gefunden."}
          </p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead><tr><th>Name</th><th>{isProxmoxHost ? "Art" : "Image"}</th><th>Zustand</th>{!isProxmoxHost && <th />}</tr></thead>
              <tbody>
                {containers.map((c) => (
                  <tr key={c.id}>
                    <td>{c.name}</td>
                    <td className="mono">{c.image}</td>
                    <td>
                      <span className={`badge ${c.state === "running" ? "ok" : ""}`}>{c.status}</span>
                    </td>
                    {!isProxmoxHost && (
                      <td style={{ whiteSpace: "nowrap", width: 1 }}>
                        <button className="secondary small" disabled={busyId !== ""}
                                onClick={() => void runAction(c.id, "start")}>Starten</button>{" "}
                        <button className="secondary small" disabled={busyId !== ""}
                                onClick={() => void runAction(c.id, "stop")}>Stoppen</button>{" "}
                        <button className="secondary small" disabled={busyId !== ""}
                                onClick={() => void runAction(c.id, "restart")}>Neu starten</button>{" "}
                        <button className="secondary small"
                                onClick={() => setConsoleContainerId(consoleContainerId === c.id ? null : c.id)}>
                          {consoleContainerId === c.id ? "Konsole schließen" : "Konsole"}
                        </button>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      )}

      {!isProxmoxHost && consoleContainerId && (
        <div style={{ marginTop: 16 }}>
          <Terminal
            wsUrl={api.remoteDockerConsoleWsUrl(systemId, accountId, consoleContainerId)}
            onClose={() => setConsoleContainerId(null)}
          />
        </div>
      )}
    </div>
  );
}
