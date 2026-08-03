import { useEffect, useState } from "react";
import { api, type ApiToken, type ModelOption, type PasswordPolicy, type SettingsResponse } from "../lib/api";
import { useAuth } from "../App";

const KEY_FIELD: Record<string, string> = {
  CLAUDE: "claudeApiKey", OPENAI: "openAiApiKey", GEMINI: "geminiApiKey",
  DEEPSEEK: "deepseekApiKey", OLLAMA: "ollamaApiKey",
};
const MODEL_FIELD: Record<string, string> = {
  CLAUDE: "claudeModel", OPENAI: "openAiModel", GEMINI: "geminiModel",
  DEEPSEEK: "deepseekModel", OLLAMA: "ollamaModel",
};
const BASE_URL_FIELD: Record<string, string> = {
  CLAUDE: "claudeBaseUrl", OPENAI: "openAiBaseUrl", DEEPSEEK: "deepseekBaseUrl", OLLAMA: "ollamaBaseUrl",
};

type Tab = "general" | "llm" | "scan" | "monitor" | "mcp" | "account" | "about";

export default function SettingsPage() {
  const { isAdmin, user } = useAuth();
  const [tab, setTab] = useState<Tab>(isAdmin ? "general" : "account");
  const [data, setData] = useState<SettingsResponse | null>(null);
  const [form, setForm] = useState<Record<string, any>>({});
  const [notice, setNotice] = useState<{ kind: "ok" | "error" | "info"; text: string } | null>(null);
  const [busy, setBusy] = useState("");

  useEffect(() => {
    api.getSettings().then((r) => {
      setData(r);
      setForm(r.settings);
    });
  }, []);

  function set(key: string, value: any) {
    setForm((current) => ({ ...current, [key]: value }));
  }

  async function save(patch: Record<string, any>) {
    setBusy("save");
    try {
      const { settings } = await api.updateSettings(patch);
      setForm(settings);
      setNotice({ kind: "ok", text: "Gespeichert." });
    } catch (e) {
      setNotice({ kind: "error", text: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy("");
    }
  }

  async function testConnection() {
    setBusy("test");
    setNotice(null);
    try {
      const r = await api.testLlm(form.llmProvider, form);
      setNotice({
        kind: r.ok ? "ok" : "error",
        text: r.ok ? `Verbindung steht (Modell: ${r.model}). Antwort: ${r.message}` : r.message,
      });
    } catch (e) {
      setNotice({ kind: "error", text: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy("");
    }
  }

  async function refreshModels() {
    setBusy("models");
    setNotice(null);
    try {
      const r = await api.refreshModels(form.llmProvider, form);
      setNotice({ kind: r.ok ? "ok" : "error", text: r.message });
      if (r.ok) setData(await api.getSettings());
    } catch (e) {
      setNotice({ kind: "error", text: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy("");
    }
  }

  if (!data) return <span className="spinner" />;

  const provider: string = form.llmProvider ?? "DEEPSEEK";
  const liveModels: ModelOption[] = form.providerModelCache?.[provider]?.models ?? [];
  const catalogModels = data.catalog[provider] ?? [];
  const modelOptions = liveModels.length > 0 ? liveModels : catalogModels;

  const TABS: [Tab, string][] = isAdmin
    ? [["general", "Allgemein"], ["llm", "KI-Assistent"], ["scan", "Netzwerk-Scan"],
       ["monitor", "Überwachung"], ["mcp", "MCP-Server"], ["account", "Konto"], ["about", "Über"]]
    : [["account", "Konto"], ["about", "Über"]];

  return (
    <>
      <div className="page-header">
        <div>
          <h1>Einstellungen</h1>
          <p>Anbieter für den KI-Assistenten, Umfang des Netzwerk-Scans und das eigene Konto.</p>
        </div>
      </div>

      <div className="row" style={{ marginBottom: 18 }}>
        {TABS.map(([value, label]) => (
          <button key={value} className={tab === value ? "" : "secondary"} onClick={() => setTab(value)}>
            {label}
          </button>
        ))}
      </div>

      {notice && <div className={`notice ${notice.kind}`}>{notice.text}</div>}

      {tab === "general" && isAdmin && (
        <div className="card">
          <h2>Allgemein</h2>
          <div className="field">
            <label>Name deines Zuhauses</label>
            <input value={form.homeName ?? ""} onChange={(e) => set("homeName", e.target.value)} />
            <div className="field-hint">
              Erscheint als Überschrift auf der Übersicht und in der Dokumentation.
            </div>
          </div>
          <button onClick={() => void save({ homeName: form.homeName })} disabled={busy !== ""}>
            Speichern
          </button>
        </div>
      )}

      {tab === "llm" && isAdmin && (
        <div className="card">
          <h2>KI-Assistent</h2>
          <p className="muted">
            Der Assistent begleitet bei Störungen und schreibt die Dokumentation in verständlicher
            Sprache. Ohne Anbieter funktioniert HomeAtlas weiter — nur eben ohne KI-Texte und ohne Chat.
          </p>

          <div className="field">
            <label>Anbieter</label>
            <select value={provider} onChange={(e) => set("llmProvider", e.target.value)}>
              {Object.entries(data.providers).map(([value, label]) => (
                <option key={value} value={value}>{label}</option>
              ))}
            </select>
          </div>

          {provider !== "OLLAMA" && (
            <div className="field">
              <label>API-Schlüssel</label>
              <input
                type="password"
                autoComplete="off"
                value={form[KEY_FIELD[provider]] ?? ""}
                onChange={(e) => set(KEY_FIELD[provider], e.target.value)}
              />
              <div className="field-hint">
                Wird nur auf deinem eigenen Server gespeichert und nie im Klartext zurückgegeben.
              </div>
            </div>
          )}

          {BASE_URL_FIELD[provider] && (
            <div className="field">
              <label>Server-Adresse (optional)</label>
              <input
                placeholder={provider === "OLLAMA" ? "http://localhost:11434/v1" : "Standard des Anbieters"}
                value={form[BASE_URL_FIELD[provider]] ?? ""}
                onChange={(e) => set(BASE_URL_FIELD[provider], e.target.value)}
              />
              <div className="field-hint">
                Nur nötig für eigene Server, Proxys oder OpenAI-kompatible Dienste wie OpenRouter.
              </div>
            </div>
          )}

          <div className="field">
            <label>Modell</label>
            <select value={form[MODEL_FIELD[provider]] ?? "auto"}
                    onChange={(e) => set(MODEL_FIELD[provider], e.target.value)}>
              <option value="auto">Automatisch wählen</option>
              {modelOptions.map((m) => (
                <option key={m.id} value={m.id}>
                  {m.label}{"price_tier" in m && m.price_tier ? ` · ${m.price_tier}` : ""}
                </option>
              ))}
            </select>
            <div className="field-hint">
              {liveModels.length > 0
                ? `${liveModels.length} Modelle direkt vom Anbieter geladen.`
                : "Vorauswahl. Über „Modelle laden“ holst du die Liste, die dein Zugang wirklich nutzen darf."}
            </div>
          </div>

          <div className="row">
            <button onClick={() => void save(form)} disabled={busy !== ""}>Speichern</button>
            <button className="secondary" onClick={() => void testConnection()} disabled={busy !== ""}>
              {busy === "test" ? "Teste…" : "Verbindung testen"}
            </button>
            <button className="secondary" onClick={() => void refreshModels()} disabled={busy !== ""}>
              {busy === "models" ? "Lade…" : "Modelle laden"}
            </button>
          </div>
        </div>
      )}

      {tab === "scan" && isAdmin && (
        <div className="card">
          <h2>Netzwerk-Scan</h2>

          <div className="field">
            <label>Netzwerk-Bereiche</label>
            <input
              placeholder="192.168.1.0/24, 192.168.2.0/24 — leer = automatisch erkennen"
              value={(form.scanSubnets ?? []).join(", ")}
              onChange={(e) => set("scanSubnets", e.target.value.split(",").map((s) => s.trim()).filter(Boolean))}
            />
            <div className="field-hint">Leer lassen, wenn HomeAtlas den Bereich selbst bestimmen soll.</div>
          </div>

          <div className="field">
            <label>Einzelziele außerhalb dieser Bereiche</label>
            <input
              placeholder="z. B. 10.1.1.1, 192.168.178.1, nas.fritz.box"
              value={(form.scanExtraTargets ?? []).join(", ")}
              onChange={(e) => set("scanExtraTargets", e.target.value.split(",").map((s) => s.trim()).filter(Boolean))}
            />
            <div className="field-hint">
              Für Geräte, die nicht im eigenen Netzbereich liegen — etwa ein Router auf 10.1.1.1,
              während das Heimnetz 192.168.1.x nutzt, oder eine VM hinter einer Bridge. Adressen von
              Geräten, die du selbst angelegt hast, werden automatisch mitgeprüft.
            </div>
          </div>

          <div className="field">
            <label>Adressen ausnehmen</label>
            <input
              placeholder="z. B. 192.168.1.50, 192.168.1.51"
              value={(form.scanExcludeIps ?? []).join(", ")}
              onChange={(e) => set("scanExcludeIps", e.target.value.split(",").map((s) => s.trim()).filter(Boolean))}
            />
            <div className="field-hint">Geräte, die nicht angesprochen werden sollen.</div>
          </div>

          <div className="grid cols-2">
            <div className="field">
              <label>Wartezeit je Anfrage (Millisekunden)</label>
              <input type="number" min={100} max={5000} value={form.scanTimeoutMs ?? 700}
                     onChange={(e) => set("scanTimeoutMs", Number(e.target.value))} />
              <div className="field-hint">Höher = zuverlässiger bei langsamen Geräten, aber langsamer.</div>
            </div>
            <div className="field">
              <label>Gleichzeitige Anfragen</label>
              <input type="number" min={8} max={512} value={form.scanConcurrency ?? 128}
                     onChange={(e) => set("scanConcurrency", Number(e.target.value))} />
              <div className="field-hint">Niedriger, falls schwache Geräte im Netz Probleme machen.</div>
            </div>
          </div>

          <div className="grid cols-2">
            <label className="row" style={{ cursor: "pointer", fontWeight: 400, color: "var(--text)" }}>
              <input type="checkbox" style={{ width: "auto" }} checked={form.scanAutoEnabled ?? false}
                     onChange={(e) => set("scanAutoEnabled", e.target.checked)} />
              Scans automatisch wiederholen (statt nur auf Knopfdruck)
            </label>
            <div className="field">
              <label>Intervall (Stunden)</label>
              <input type="number" min={1} max={720} value={form.scanAutoIntervalHours ?? 24}
                     disabled={!form.scanAutoEnabled}
                     onChange={(e) => set("scanAutoIntervalHours", Number(e.target.value))} />
              <div className="field-hint">
                Mindestabstand zwischen zwei automatischen Scans -- ein manueller Scan zählt
                mit. Betrifft auch, wie oft Konfigsicherungen (Switches, Router, Omada) erneuert
                werden.
              </div>
            </div>
          </div>

          <div className="field">
            <label>Aufbewahrte Konfigsicherungen je Gerät</label>
            <input type="number" min={1} max={1000} value={form.configVersionKeep ?? 50}
                   onChange={(e) => set("configVersionKeep", Number(e.target.value))} />
            <div className="field-hint">
              Ältere Versionen werden über dieser Anzahl automatisch gelöscht (je Gerät und
              Sicherungsart).
            </div>
          </div>

          {([
            ["scanEnableMdns", "Smart-Home-Geräte über mDNS/Bonjour finden"],
            ["scanEnableSsdp", "Geräte über UPnP finden (TVs, Router, Drucker)"],
            ["scanEnableHttpBanner", "Weboberflächen auslesen, um Geräte zu erkennen"],
            ["scanEnableDocker", "Docker-Container auf dem Server erfassen"],
            ["scanEnableOmada", "Access Points und Switches über den Omada Controller erfassen"],
            ["scanUseLlm", "KI zur Einordnung unbekannter Geräte und für die Doku-Texte nutzen"],
            ["scanUseCredentials", "Freigegebene Zugänge zum Auslesen der Geräte verwenden (nur lesend)"],
          ] as const).map(([key, label]) => (
            <label key={key} className="row" style={{ marginBottom: 10, cursor: "pointer", fontWeight: 400, color: "var(--text)" }}>
              <input type="checkbox" style={{ width: "auto" }} checked={form[key] ?? true}
                     onChange={(e) => set(key, e.target.checked)} />
              {label}
            </label>
          ))}

          <div className="row" style={{ marginTop: 16 }}>
            <button onClick={() => void save(form)} disabled={busy !== ""}>Speichern</button>
            <button className="secondary" disabled={busy !== ""} onClick={async () => {
              setBusy("oui");
              const r = await api.refreshOui();
              setNotice({ kind: r.ok ? "ok" : "error", text: r.message });
              setBusy("");
            }}>
              {busy === "oui" ? "Lade…" : "Hersteller-Datenbank aktualisieren"}
            </button>
          </div>
          <p className="field-hint" style={{ marginTop: 10 }}>
            Hersteller-Datenbank: {data.ouiLoaded ? `${data.ouiEntries.toLocaleString("de-DE")} Einträge geladen` : "noch nicht geladen"}
            {" · "}Docker-Zugriff: {data.dockerAvailable ? "verfügbar" : "nicht eingebunden"}
          </p>
        </div>
      )}

      {tab === "scan" && isAdmin && (
        <div className="card">
          <h2>Standard-Zugang für die Geräteabfrage</h2>
          <p className="muted" style={{ marginTop: -6 }}>
            Wird nur bei Geräten benutzt, für die <em>kein eigener</em> Zugang hinterlegt ist —
            praktisch, wenn auf allen Servern derselbe Wartungszugang existiert.
          </p>
          <div className="notice info">
            Aus gutem Grund eng begrenzt: der Zugang wird nur bei Servern, NAS, VMs und PCs
            versucht, und nur wenn der passende Port beim Scan offen war. Router und unbekannte
            Geräte bleiben außen vor — dort richtet ein fehlgeschlagener Anmeldeversuch am ehesten
            Schaden an (manche sperren das Konto nach mehreren Fehlversuchen).
          </div>

          <label className="row" style={{ cursor: "pointer", fontWeight: 400, color: "var(--text)", marginBottom: 12 }}>
            <input type="checkbox" style={{ width: "auto" }} checked={form.defaultCredentialEnabled ?? false}
                   onChange={(e) => set("defaultCredentialEnabled", e.target.checked)} />
            Standard-Zugang verwenden
          </label>

          {form.defaultCredentialEnabled && (
            <div className="grid cols-2">
              <div className="field">
                <label>Benutzername</label>
                <input placeholder="z. B. root" value={form.defaultCredentialUsername ?? ""}
                       autoComplete="off"
                       onChange={(e) => set("defaultCredentialUsername", e.target.value)} />
              </div>
              <div className="field">
                <label>Port (optional)</label>
                <input type="number" min={0} max={65535} placeholder="Standard: 22"
                       value={form.defaultCredentialPort || ""}
                       onChange={(e) => set("defaultCredentialPort", Number(e.target.value))} />
              </div>
              <div className="field" style={{ gridColumn: "1 / -1" }}>
                <label className="row" style={{ cursor: "pointer", fontWeight: 400, color: "var(--text)" }}>
                  <input type="checkbox" style={{ width: "auto" }} checked={form.defaultCredentialIsKey ?? false}
                         onChange={(e) => set("defaultCredentialIsKey", e.target.checked)} />
                  Es handelt sich um einen SSH-Schlüssel (statt eines Passworts)
                </label>
              </div>
              <div className="field" style={{ gridColumn: "1 / -1" }}>
                <label>{form.defaultCredentialIsKey ? "Privater SSH-Schlüssel" : "Passwort"}</label>
                {form.defaultCredentialIsKey ? (
                  <textarea style={{ minHeight: 130 }} spellCheck={false}
                            placeholder={form.hasDefaultCredentialSecret ? "unverändert lassen" : "-----BEGIN OPENSSH PRIVATE KEY-----"}
                            value={form.defaultCredentialSecret ?? ""}
                            onChange={(e) => set("defaultCredentialSecret", e.target.value)} />
                ) : (
                  <input type="password" autoComplete="new-password"
                         placeholder={form.hasDefaultCredentialSecret ? "unverändert lassen" : ""}
                         value={form.defaultCredentialSecret ?? ""}
                         onChange={(e) => set("defaultCredentialSecret", e.target.value)} />
                )}
                <div className="field-hint">
                  {form.hasDefaultCredentialSecret
                    ? "Es ist etwas hinterlegt. Leer lassen, um es beizubehalten."
                    : "Wird verschlüsselt gespeichert und nie zurückgegeben."}
                </div>
              </div>
              {form.defaultCredentialIsKey && (
                <div className="field">
                  <label>Passphrase des Schlüssels (falls vorhanden)</label>
                  <input type="password" autoComplete="new-password"
                         placeholder={form.hasDefaultCredentialPassphrase ? "unverändert lassen" : ""}
                         value={form.defaultCredentialPassphrase ?? ""}
                         onChange={(e) => set("defaultCredentialPassphrase", e.target.value)} />
                </div>
              )}
            </div>
          )}

          <button onClick={() => void save(form)} disabled={busy !== ""}>Speichern</button>
        </div>
      )}

      {tab === "monitor" && isAdmin && (
        <div className="card">
          <h2>Dauerüberwachung</h2>
          <p className="muted" style={{ marginTop: -6 }}>
            Wichtige Geräte werden laufend geprüft, nicht nur beim Scan. Geräte mit der Bedeutung
            „kritisch" kommen automatisch dazu.
          </p>
          <label className="row" style={{ cursor: "pointer", fontWeight: 400, color: "var(--text)", marginBottom: 12 }}>
            <input type="checkbox" style={{ width: "auto" }} checked={form.monitorEnabled ?? true}
                   onChange={(e) => set("monitorEnabled", e.target.checked)} />
            Dauerüberwachung aktiv
          </label>
          <div className="grid cols-2">
            <div className="field">
              <label>Prüfabstand (Sekunden)</label>
              <input type="number" min={5} max={600} value={form.monitorIntervalSeconds ?? 10}
                     onChange={(e) => set("monitorIntervalSeconds", Number(e.target.value))} />
              <div className="field-hint">
                Ein Ausfall wird erst nach zwei aufeinanderfolgenden Fehlversuchen gemeldet — ein
                einzelner verlorener Ping löst nichts aus.
              </div>
            </div>
            <div className="field">
              <label>Wartezeit je Prüfung (Millisekunden)</label>
              <input type="number" min={200} max={10000} value={form.monitorTimeoutMs ?? 1500}
                     onChange={(e) => set("monitorTimeoutMs", Number(e.target.value))} />
            </div>
            <div className="field" style={{ gridColumn: "1 / -1" }}>
              <label>Namen für den DNS-Test</label>
              <input
                value={(form.dnsTestNames ?? []).join(", ")}
                onChange={(e) => set("dnsTestNames", e.target.value.split(",").map((s) => s.trim()).filter(Boolean))}
              />
              <div className="field-hint">
                Bewusst externe Adressen: nur lokale Namen aufzulösen gelingt auch dann noch, wenn
                die Weiterleitung ins Internet defekt ist — genau der häufigste Fehler.
              </div>
            </div>
          </div>
          <button onClick={() => void save(form)} disabled={busy !== ""}>Speichern</button>
        </div>
      )}

      {tab === "mcp" && isAdmin && <McpTab />}

      {tab === "account" && <AccountTab username={user?.username ?? ""} totpEnabled={Boolean(user?.totpEnabled)} />}

      {tab === "about" && (
        <div className="card">
          <div className="row" style={{ gap: 16, alignItems: "center", marginBottom: 12 }}>
            <img src="/icon.svg" alt="" width={64} height={64} style={{ borderRadius: 14 }} />
            <div>
              <h2 style={{ margin: 0 }}>HomeAtlas</h2>
              <p className="muted" style={{ margin: 0 }}>
                Die Dokumentation deines Heimnetzes — automatisch erstellt, in verständlicher Sprache.
              </p>
            </div>
          </div>
          <img src="/about.svg" alt="Vom Netzwerk-Scan über die Erkennung zur fertigen Dokumentation"
               style={{ width: "100%", maxWidth: 800, borderRadius: 12, marginBottom: 16 }} />
          <div className="table-wrap">
            <table>
              <tbody>
                <tr><th>Version</th><td className="mono">{__APP_VERSION__}</td></tr>
                <tr><th>Build</th><td className="mono">{__BUILD_SHA__}</td></tr>
                {__BUILD_TIME__ && <tr><th>Erstellt am</th><td className="mono">{__BUILD_TIME__}</td></tr>}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </>
  );
}

function McpTab() {
  const [tokens, setTokens] = useState<ApiToken[] | null>(null);
  const [label, setLabel] = useState("");
  const [freshToken, setFreshToken] = useState<ApiToken | null>(null);
  const [notice, setNotice] = useState<{ kind: "ok" | "error"; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const mcpUrl = `${window.location.origin}/api/mcp`;

  function load() {
    api.listMcpTokens().then((r) => setTokens(r.tokens)).catch((e) => setNotice({ kind: "error", text: e.message }));
  }

  useEffect(load, []);

  async function create() {
    if (!label.trim()) return;
    setBusy(true);
    setNotice(null);
    try {
      const { token } = await api.createMcpToken(label.trim());
      setFreshToken(token);
      setLabel("");
      load();
    } catch (e) {
      setNotice({ kind: "error", text: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(false);
    }
  }

  async function remove(id: string) {
    if (!window.confirm("Dieses Token wirklich löschen? Clients, die es benutzen, verlieren sofort den Zugriff.")) return;
    await api.deleteMcpToken(id);
    if (freshToken?.id === id) setFreshToken(null);
    load();
  }

  return (
    <div className="card">
      <h2>MCP-Server</h2>
      <p className="muted" style={{ marginTop: -6 }}>
        Macht dieselben lesenden Auskünfte, die auch der Chat-Assistent nutzt — Geräte,
        Dokumentation, Live-Diagnosen — über das Model Context Protocol für externe Programme wie
        Claude Desktop erreichbar. Keine Passwörter, nichts wird verändert; nur mit einem hier
        erzeugten Token nutzbar.
      </p>
      <div className="field">
        <label>Server-Adresse</label>
        <input readOnly value={mcpUrl} className="mono" onClick={(e) => e.currentTarget.select()} />
        <div className="field-hint">
          Als Remote-MCP-Server eintragen, dazu eines der Tokens unten als Bearer-Zugangsdaten.
        </div>
      </div>

      {notice && <div className={`notice ${notice.kind}`}>{notice.text}</div>}

      {freshToken?.token && (
        <div className="notice ok">
          Token erzeugt: <code className="mono">{freshToken.token}</code>
          <br />
          Wird nur <strong>jetzt einmal</strong> angezeigt — bitte kopieren. Danach lässt es sich
          nicht mehr nachlesen (nur widerrufen und neu erzeugen).
        </div>
      )}

      <div className="row" style={{ marginBottom: 14 }}>
        <input
          style={{ flex: 1, minWidth: 200 }}
          placeholder="Bezeichnung, z. B. Claude Desktop"
          value={label}
          onChange={(e) => setLabel(e.target.value)}
        />
        <button onClick={() => void create()} disabled={busy || !label.trim()}>Token erzeugen</button>
      </div>

      {tokens === null ? (
        <span className="spinner" />
      ) : tokens.length === 0 ? (
        <p className="muted">Noch kein Token erzeugt.</p>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr><th>Bezeichnung</th><th>Erstellt</th><th>Zuletzt benutzt</th><th /></tr>
            </thead>
            <tbody>
              {tokens.map((t) => (
                <tr key={t.id}>
                  <td>{t.label}</td>
                  <td className="muted">{new Date(t.createdAt).toLocaleString("de-DE")}</td>
                  <td className="muted">{t.lastUsedAt ? new Date(t.lastUsedAt).toLocaleString("de-DE") : "noch nie"}</td>
                  <td style={{ width: 1 }}>
                    <button className="danger" onClick={() => void remove(t.id)}>Widerrufen</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function AccountTab({ username, totpEnabled }: { username: string; totpEnabled: boolean }) {
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [repeat, setRepeat] = useState("");
  const [notice, setNotice] = useState<{ kind: "ok" | "error"; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [policy, setPolicy] = useState<PasswordPolicy | null>(null);

  useEffect(() => {
    api.passwordPolicy().then(setPolicy).catch(() => setPolicy(null));
  }, []);

  async function submit() {
    if (newPassword !== repeat) {
      setNotice({ kind: "error", text: "Die beiden neuen Passwörter stimmen nicht überein." });
      return;
    }
    setBusy(true);
    try {
      await api.changePassword(currentPassword, newPassword);
      setNotice({ kind: "ok", text: "Passwort geändert." });
      setCurrentPassword("");
      setNewPassword("");
      setRepeat("");
    } catch (e) {
      setNotice({ kind: "error", text: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card">
      <h2>Konto</h2>
      <p className="muted">Angemeldet als <strong>{username}</strong>.</p>
      {notice && <div className={`notice ${notice.kind}`}>{notice.text}</div>}
      <div className="field">
        <label>Aktuelles Passwort</label>
        <input type="password" autoComplete="current-password" value={currentPassword}
               onChange={(e) => setCurrentPassword(e.target.value)} />
      </div>
      <div className="field">
        <label>Neues Passwort</label>
        <input type="password" autoComplete="new-password" value={newPassword}
               onChange={(e) => setNewPassword(e.target.value)} />
        {policy && (
          <ul className="field-hint" style={{ margin: "6px 0 0", paddingLeft: "1.1em" }}>
            {policy.rules.map((rule) => <li key={rule}>{rule}</li>)}
          </ul>
        )}
      </div>
      <div className="field">
        <label>Neues Passwort wiederholen</label>
        <input type="password" autoComplete="new-password" value={repeat}
               onChange={(e) => setRepeat(e.target.value)} />
      </div>
      <button onClick={() => void submit()}
              disabled={busy || !currentPassword || newPassword.length < (policy?.minLength ?? 10)}>
        {busy ? "Ändere…" : "Passwort ändern"}
      </button>

      <MfaSection enabled={totpEnabled} />
    </div>
  );
}

/** Zwei-Faktor-Anmeldung ist inzwischen Pflicht (siehe MfaEnrollPage) -- die Einrichtung passiert
 *  dort direkt nach dem Login, nicht mehr hier. Diese Karte zeigt nur noch den Status; es gibt
 *  bewusst keine Selbstabschaltung mehr, nur ein Administrator kann sie zurücksetzen
 *  (Benutzerverwaltung), damit ein gestohlenes Passwort allein sie nicht aushebeln kann. */
function MfaSection({ enabled }: { enabled: boolean }) {
  return (
    <div style={{ marginTop: 28, paddingTop: 20, borderTop: "1px solid var(--border)" }}>
      <div className="row" style={{ justifyContent: "space-between", marginBottom: 8 }}>
        <h3 style={{ margin: 0 }}>Zwei-Faktor-Anmeldung (Pflicht)</h3>
        <span className={`badge ${enabled ? "ok" : "warn"}`}>{enabled ? "aktiv" : "noch nicht eingerichtet"}</span>
      </div>
      <p className="muted" style={{ marginBottom: 0 }}>
        Zusätzlich zum Passwort ein Code aus einer Authenticator-App (Aegis, 2FAS, Google
        Authenticator, 1Password …). Wer dann dein Passwort kennt, kommt trotzdem nicht hinein.
        Gerät mit der App verloren? Ein Administrator setzt die Zwei-Faktor-Anmeldung unter
        „Benutzer" zurück — danach wird sie beim nächsten Login neu eingerichtet.
      </p>
    </div>
  );
}
