import { useEffect, useState } from "react";
import { api, type ModelOption, type SettingsResponse } from "../lib/api";
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

type Tab = "general" | "llm" | "scan" | "account" | "about";

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
       ["account", "Konto"], ["about", "Über"]]
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

          {([
            ["scanEnableMdns", "Smart-Home-Geräte über mDNS/Bonjour finden"],
            ["scanEnableSsdp", "Geräte über UPnP finden (TVs, Router, Drucker)"],
            ["scanEnableHttpBanner", "Weboberflächen auslesen, um Geräte zu erkennen"],
            ["scanEnableDocker", "Docker-Container auf dem Server erfassen"],
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

      {tab === "account" && <AccountTab username={user?.username ?? ""} />}

      {tab === "about" && (
        <div className="card">
          <h2>Über HomeAtlas</h2>
          <p className="muted">Die Dokumentation deines Heimnetzes — automatisch erstellt, in verständlicher Sprache.</p>
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

function AccountTab({ username }: { username: string }) {
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [repeat, setRepeat] = useState("");
  const [notice, setNotice] = useState<{ kind: "ok" | "error"; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

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
        <div className="field-hint">Mindestens 8 Zeichen.</div>
      </div>
      <div className="field">
        <label>Neues Passwort wiederholen</label>
        <input type="password" autoComplete="new-password" value={repeat}
               onChange={(e) => setRepeat(e.target.value)} />
      </div>
      <button onClick={() => void submit()} disabled={busy || !currentPassword || newPassword.length < 8}>
        {busy ? "Ändere…" : "Passwort ändern"}
      </button>
    </div>
  );
}
