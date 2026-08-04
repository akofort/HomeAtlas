import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api, type Account, type AccountAssignment, type System } from "../lib/api";

const CATEGORIES: [string, string][] = [
  ["contract", "Vertrag / Kundenkonto"],
  ["login", "Anmeldung an Gerät oder Dienst"],
  ["sshkey", "SSH-Schlüssel"],
  ["snmp", "SNMP (Community-Zeichenkette)"],
  ["omada", "Omada Controller (Open API)"],
  ["homeassistant", "Home Assistant (Long-Lived Access Token)"],
  ["proxmox", "Proxmox VE (API-Token)"],
  ["adguard", "AdGuard Home (Basic Auth)"],
  ["wifi", "WLAN-Zugang"],
  ["apikey", "API-Schlüssel"],
  ["other", "Sonstiges"],
];

const CATEGORY_LABEL = Object.fromEntries(CATEGORIES);

interface Draft {
  id: string | null;
  systemId: string;
  label: string;
  category: string;
  username: string;
  secret: string;
  passphrase: string;
  url: string;
  notes: string;
  allowProbe: boolean;
  port: number;
}

const emptyDraft = (): Draft => ({
  id: null, systemId: "", label: "", category: "contract",
  username: "", secret: "", passphrase: "", url: "", notes: "", allowProbe: false, port: 0,
});

export default function AccountsPage() {
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [systems, setSystems] = useState<System[]>([]);
  const [kindLabels, setKindLabels] = useState<Record<string, string>>({});
  const [draft, setDraft] = useState<Draft | null>(null);
  const [assignments, setAssignments] = useState<AccountAssignment[]>([]);
  const [assignType, setAssignType] = useState<"kind" | "subnet" | "system">("kind");
  const [assignValue, setAssignValue] = useState("");
  const [secrets, setSecrets] = useState<Record<string, string>>({});
  const [query, setQuery] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [deployingId, setDeployingId] = useState<string | null>(null);
  const [deployLoginId, setDeployLoginId] = useState("");

  async function reload() {
    const [a, s] = await Promise.all([api.listAccounts(), api.listSystems()]);
    setAccounts(a.accounts);
    setSystems(s.systems);
    setKindLabels(s.kindLabels);
  }

  useEffect(() => {
    reload()
      .catch((e) => setError(e instanceof Error ? e.message : String(e)))
      .finally(() => setLoading(false));
  }, []);

  const systemName = useMemo(
    () => Object.fromEntries(systems.map((s) => [s.id, s.name])) as Record<string, string>,
    [systems],
  );

  const visible = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return accounts;
    return accounts.filter((a) =>
      [a.label, a.username, a.url, a.notes, systemName[a.systemId ?? ""] ?? ""]
        .join(" ")
        .toLowerCase()
        .includes(needle),
    );
  }, [accounts, query, systemName]);

  function startEdit(account: Account) {
    setNotice("");
    setAssignments([]);
    setDraft({
      id: account.id,
      systemId: account.systemId ?? "",
      label: account.label,
      category: account.category,
      username: account.username,
      // Never prefilled: the plaintext is fetched only on explicit "Anzeigen", and a blank field
      // means "leave the stored password alone" (see the backend's update_account).
      secret: "",
      passphrase: "",
      url: account.url,
      notes: account.notes,
      allowProbe: Boolean(account.allowProbe),
      port: account.port ?? 0,
    });
    api.listAccountAssignments(account.id).then((r) => setAssignments(r.assignments)).catch(() => {});
  }

  async function addAssignment() {
    if (!draft?.id || !assignValue.trim()) return;
    setBusy(true);
    setError("");
    try {
      const next = [
        ...assignments.map((a) => ({ targetType: a.targetType, targetValue: a.targetValue })),
        { targetType: assignType, targetValue: assignValue.trim() },
      ];
      const r = await api.setAccountAssignments(draft.id, next);
      setAssignments(r.assignments);
      setAssignValue("");
      await reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function removeAssignment(assignment: AccountAssignment) {
    if (!draft?.id) return;
    setBusy(true);
    setError("");
    try {
      const next = assignments
        .filter((a) => a.id !== assignment.id)
        .map((a) => ({ targetType: a.targetType, targetValue: a.targetValue }));
      const r = await api.setAccountAssignments(draft.id, next);
      setAssignments(r.assignments);
      await reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function save() {
    if (!draft || !draft.label.trim()) return;
    setBusy(true);
    setError("");
    try {
      const body = {
        systemId: draft.systemId || null,
        label: draft.label.trim(),
        category: draft.category,
        username: draft.username,
        secret: draft.secret,
        passphrase: draft.passphrase,
        url: draft.url,
        notes: draft.notes,
        allowProbe: draft.allowProbe,
        port: Number(draft.port) || 0,
      };
      if (draft.id) {
        await api.updateAccount(draft.id, body);
        // A changed password invalidates whatever was revealed on screen.
        setSecrets((current) => {
          const next = { ...current };
          delete next[draft.id!];
          return next;
        });
      } else {
        await api.createAccount(body);
      }
      await reload();
      setNotice(draft.id ? "Zugang aktualisiert." : "Zugang angelegt.");
      setDraft(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function generateKey() {
    if (!draft || !draft.systemId) return;
    setBusy(true);
    setError("");
    try {
      const { publicKey } = await api.generateSshKey(draft.systemId, draft.label.trim() || "SSH-Schlüssel (HomeAtlas)");
      await reload();
      setNotice(`Schlüssel erzeugt. Öffentlicher Teil: ${publicKey}`);
      setDraft(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function deployKey(account: Account) {
    if (!deployLoginId) return;
    setBusy(true);
    setError("");
    try {
      const r = await api.deploySshKey(account.id, deployLoginId);
      setNotice(r.changed
        ? `Schlüssel auf „${systemName[account.systemId ?? ""] ?? "Gerät"}“ eingespielt.`
        : `Schlüssel war dort schon hinterlegt.`);
      setDeployingId(null);
      setDeployLoginId("");
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function reveal(id: string) {
    try {
      const { secret } = await api.revealSecret(id);
      setSecrets((current) => ({ ...current, [id]: secret }));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  async function remove(account: Account) {
    if (!window.confirm(`„${account.label}" wirklich löschen? Das gespeicherte Passwort geht dabei verloren.`)) return;
    try {
      await api.deleteAccount(account.id);
      await reload();
      setNotice("Zugang gelöscht.");
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <>
      <div className="page-header">
        <div>
          <h1>Zugänge und Konten</h1>
          <p>
            Zugangsdaten zu Geräten, Verträgen und Diensten. Passwörter werden verschlüsselt
            gespeichert, erscheinen nie in der Dokumentation und werden dem KI-Assistenten nie
            übergeben — er sieht nur, <em>dass</em> ein Zugang hinterlegt ist.
          </p>
        </div>
        {!draft && <button onClick={() => { setNotice(""); setAssignments([]); setDraft(emptyDraft()); }}>+ Neuer Zugang</button>}
      </div>

      {error && <div className="notice error">{error}</div>}
      {notice && <div className="notice ok">{notice}</div>}

      <div className="notice info">
        <strong>HomeAtlas ist kein Passwort-Manager.</strong> Was hier steht, gehört zur
        Dokumentation der Technik: Router-Zugang, NAS-Login, Kundennummer beim Anbieter — damit man
        im Störungsfall schnell drankommt. Für persönliche Passwörter, Bankzugänge und alles, was
        über einzelne Geräte hinausgeht, gehört ein echter Passwort-Safe her:{" "}
        <a href="https://bitwarden.com/" target="_blank" rel="noreferrer">Bitwarden</a> (auch
        selbst gehostet als{" "}
        <a href="https://github.com/dani-garcia/vaultwarden" target="_blank" rel="noreferrer">Vaultwarden</a>),{" "}
        <a href="https://keepassxc.org/" target="_blank" rel="noreferrer">KeePassXC</a> oder{" "}
        <a href="https://1password.com/" target="_blank" rel="noreferrer">1Password</a>. Die bieten
        Browser-Integration, Freigaben und Notfallzugriff — Dinge, die diese App bewusst nicht macht.
      </div>

      {draft && (
        <div className="card">
          <h2>{draft.id ? "Zugang bearbeiten" : "Neuer Zugang"}</h2>
          <div className="grid cols-2">
            <div className="field">
              <label>Bezeichnung</label>
              <input autoFocus placeholder="z. B. Telekom Kundenkonto" value={draft.label}
                     onChange={(e) => setDraft({ ...draft, label: e.target.value })} />
            </div>
            <div className="field">
              <label>Art</label>
              <select value={draft.category} onChange={(e) => setDraft({ ...draft, category: e.target.value })}>
                {CATEGORIES.map(([value, label]) => <option key={value} value={value}>{label}</option>)}
              </select>
            </div>
            <div className="field">
              <label>Gehört zu welchem Gerät?</label>
              <select value={draft.systemId} onChange={(e) => setDraft({ ...draft, systemId: e.target.value })}>
                <option value="">— zu keinem bestimmten Gerät —</option>
                {systems.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
              </select>
              <div className="field-hint">Verträge und Online-Konten brauchen das nicht.</div>
            </div>
            <div className="field">
              <label>
                {draft.category === "omada" ? "Client-ID"
                  : draft.category === "proxmox" ? "Token-ID (z. B. root@pam!homeatlas)"
                  : "Benutzername / Kundennummer"}
              </label>
              <input value={draft.username} autoComplete="off"
                     onChange={(e) => setDraft({ ...draft, username: e.target.value })} />
            </div>
            {draft.category === "sshkey" ? (
              <>
                {!draft.id && (
                  <div className="field" style={{ gridColumn: "1 / -1" }}>
                    <button className="secondary" type="button" onClick={() => void generateKey()}
                            disabled={busy || !draft.systemId}>
                      {busy ? "Erzeuge…" : "Neuen Schlüssel erzeugen"}
                    </button>
                    <div className="field-hint">
                      Erzeugt ein Ed25519-Schlüsselpaar für das oben gewählte Gerät und speichert es
                      direkt — ersetzt die manuelle Eingabe unten. Braucht ein gewähltes Gerät.
                    </div>
                  </div>
                )}
                <div className="field" style={{ gridColumn: "1 / -1" }}>
                  <label>Privater SSH-Schlüssel (von Hand eintragen, falls schon vorhanden)</label>
                  <textarea
                    style={{ minHeight: 150 }}
                    spellCheck={false}
                    value={draft.secret}
                    placeholder={draft.id
                      ? "unverändert lassen"
                      : "-----BEGIN OPENSSH PRIVATE KEY-----\n…\n-----END OPENSSH PRIVATE KEY-----"}
                    onChange={(e) => setDraft({ ...draft, secret: e.target.value })}
                  />
                  <div className="field-hint">
                    Der <strong>private</strong> Schlüssel, vollständig mit BEGIN- und END-Zeile.
                    Wird verschlüsselt gespeichert.
                  </div>
                </div>
                <div className="field">
                  <label>Passphrase des Schlüssels (falls vorhanden)</label>
                  <input type="password" autoComplete="new-password" value={draft.passphrase}
                         placeholder={draft.id ? "unverändert lassen" : ""}
                         onChange={(e) => setDraft({ ...draft, passphrase: e.target.value })} />
                </div>
              </>
            ) : (
              <div className="field">
                <label>
                  {draft.category === "snmp" ? "Community-Zeichenkette"
                    : draft.category === "omada" ? "Client Secret"
                    : draft.category === "homeassistant" ? "Zugriffstoken (Long-Lived Access Token)"
                    : draft.category === "proxmox" ? "Token-Secret (UUID)"
                    : "Passwort"}
                </label>
                <input type="password" autoComplete="new-password" value={draft.secret}
                       placeholder={draft.id ? "unverändert lassen" : ""}
                       onChange={(e) => setDraft({ ...draft, secret: e.target.value })} />
                <div className="field-hint">
                  {draft.id
                    ? `Leer lassen, um ${draft.category === "snmp" ? "die gespeicherte Community-Zeichenkette"
                        : draft.category === "omada" ? "das gespeicherte Client Secret"
                        : draft.category === "homeassistant" ? "das gespeicherte Zugriffstoken"
                        : draft.category === "proxmox" ? "das gespeicherte Token-Secret"
                        : "das gespeicherte Passwort"} beizubehalten.`
                    : draft.category === "homeassistant"
                      ? "Wird verschlüsselt gespeichert. Erzeugt im Profil des HA-Benutzers unter „Long-Lived Access Tokens“."
                      : draft.category === "proxmox"
                        ? "Wird verschlüsselt gespeichert. Erzeugt unter Datacenter → Berechtigungen → API-Tokens."
                        : "Wird verschlüsselt gespeichert."}
                </div>
              </div>
            )}
            <div className="field">
              <label>
                Adresse{["omada", "homeassistant", "proxmox", "adguard"].includes(draft.category) ? "" : " (optional)"}
              </label>
              <input placeholder="https://…" value={draft.url}
                     onChange={(e) => setDraft({ ...draft, url: e.target.value })} />
              {draft.category === "omada" && (
                <div className="field-hint">
                  Basis-Adresse des Controllers, z. B. https://192.168.1.10:8043 -- Client-ID und
                  Client Secret werden unter Einstellungen → Plattform-Integration → Open API im
                  Controller selbst angelegt.
                </div>
              )}
              {draft.category === "proxmox" && (
                <div className="field-hint">
                  Basis-Adresse des Proxmox-Hosts, z. B. https://192.168.1.20:8006. Dieser Zugang
                  sollte am Proxmox-Host selbst (als „Gehört zu welchem Gerät?“) hängen, damit
                  gefundene VMs/Container dort eingeordnet werden.
                </div>
              )}
              {draft.category === "homeassistant" && (
                <div className="field-hint">
                  Basis-Adresse von Home Assistant, z. B. http://192.168.1.5:8123.
                </div>
              )}
              {draft.category === "adguard" && (
                <div className="field-hint">
                  Basis-Adresse von AdGuard Home, z. B. http://192.168.1.2:3000 -- Benutzername und
                  Passwort sind die des AdGuard-Administrators (dieselben wie für die
                  Weboberfläche).
                </div>
              )}
            </div>
            {(draft.category === "sshkey" || draft.category === "login" || draft.category === "snmp") && (
              <div className="field">
                <label>Abweichender Port (optional)</label>
                <input type="number" min={0} max={65535} value={draft.port || ""}
                       placeholder={draft.category === "snmp" ? "Standard (SNMP: 161)" : "Standard (SSH: 22)"}
                       onChange={(e) => setDraft({ ...draft, port: Number(e.target.value) })} />
              </div>
            )}
            <div className="field" style={{ gridColumn: "1 / -1" }}>
              <label>Notiz (optional)</label>
              <input placeholder="z. B. Hotline 0800 …, Vertrag läuft bis …" value={draft.notes}
                     onChange={(e) => setDraft({ ...draft, notes: e.target.value })} />
            </div>
          </div>

          <label className="row" style={{ cursor: "pointer", fontWeight: 400, color: "var(--text)", marginBottom: 6 }}>
            <input type="checkbox" style={{ width: "auto" }} checked={draft.allowProbe}
                   onChange={(e) => setDraft({ ...draft, allowProbe: e.target.checked })} />
            Diesen Zugang zum Auslesen des Geräts verwenden
          </label>
          <div className="notice info" style={{ marginTop: 4 }}>
            HomeAtlas meldet sich damit am Gerät an und liest Eckdaten aus — Betriebssystem,
            Laufzeit, Speicherplatz, laufende Container, bei Netzwerkgeräten auch VLANs und
            Nachbargeräte per LLDP. Es werden <strong>ausschließlich</strong> fest einprogrammierte
            Lesebefehle ausgeführt; nichts wird geändert, installiert oder neu gestartet. Ohne
            diesen Haken bleibt der Zugang reine Ablage.
          </div>

          {draft.id ? (
            <div style={{ marginBottom: 16 }}>
              <label>Gilt zusätzlich für</label>
              <div className="field-hint" style={{ marginTop: -2, marginBottom: 8 }}>
                Ein einzelner Zugang kann über „Gehört zu welchem Gerät?“ hinaus auch für eine ganze
                Gerätekategorie, ein Subnetz oder weitere einzelne Geräte gelten — beim nächsten Scan
                wird er dort automatisch mitverwendet (sofern oben „zum Auslesen verwenden“ gesetzt ist).
              </div>
              {assignments.length > 0 && (
                <ul style={{ margin: "0 0 8px", padding: 0, listStyle: "none" }}>
                  {assignments.map((a) => (
                    <li key={a.id} className="row" style={{ marginBottom: 4, gap: 6 }}>
                      <span className="badge">
                        {a.targetType === "kind" ? `Gerätekategorie: ${kindLabels[a.targetValue] ?? a.targetValue}`
                          : a.targetType === "subnet" ? `Subnetz: ${a.targetValue}`
                          : `Gerät: ${systemName[a.targetValue] ?? a.targetValue}`}
                      </span>
                      <button type="button" className="secondary small" disabled={busy}
                              onClick={() => void removeAssignment(a)}>Entfernen</button>
                    </li>
                  ))}
                </ul>
              )}
              <div className="row" style={{ flexWrap: "nowrap" }}>
                <select style={{ width: "auto" }} value={assignType}
                        onChange={(e) => { setAssignType(e.target.value as typeof assignType); setAssignValue(""); }}>
                  <option value="kind">Gerätekategorie</option>
                  <option value="subnet">Subnetz</option>
                  <option value="system">Weiteres Gerät</option>
                </select>
                {assignType === "kind" ? (
                  <select style={{ width: "auto" }} value={assignValue} onChange={(e) => setAssignValue(e.target.value)}>
                    <option value="">— wählen —</option>
                    {Object.entries(kindLabels).map(([kind, label]) => (
                      <option key={kind} value={kind}>{label}</option>
                    ))}
                  </select>
                ) : assignType === "subnet" ? (
                  <input placeholder="z. B. 192.168.2.0/24" value={assignValue}
                         onChange={(e) => setAssignValue(e.target.value)} />
                ) : (
                  <select style={{ width: "auto" }} value={assignValue} onChange={(e) => setAssignValue(e.target.value)}>
                    <option value="">— Gerät wählen —</option>
                    {systems.filter((s) => s.id !== draft.systemId).map((s) => (
                      <option key={s.id} value={s.id}>{s.name}</option>
                    ))}
                  </select>
                )}
                <button type="button" className="secondary small" disabled={busy || !assignValue.trim()}
                        onClick={() => void addAssignment()}>Hinzufügen</button>
              </div>
            </div>
          ) : (
            <div className="notice info" style={{ marginBottom: 16 }}>
              Zuordnung zu weiteren Geräten/Gerätekategorien/Subnetzen ist nach dem ersten Speichern
              verfügbar.
            </div>
          )}

          <div className="row">
            <button onClick={() => void save()} disabled={busy || !draft.label.trim()}>
              {busy ? "Speichere…" : "Speichern"}
            </button>
            <button className="secondary" onClick={() => setDraft(null)}>Abbrechen</button>
          </div>
        </div>
      )}

      <div className="card">
        <div className="row" style={{ marginBottom: 14 }}>
          <input style={{ flex: 1, minWidth: 220 }} placeholder="Suchen nach Bezeichnung, Benutzername, Notiz …"
                 value={query} onChange={(e) => setQuery(e.target.value)} />
        </div>

        {loading ? (
          <span className="spinner" />
        ) : visible.length === 0 ? (
          <p className="muted">
            {accounts.length === 0
              ? "Noch keine Zugänge hinterlegt. Über „+ Neuer Zugang“ lässt sich der erste anlegen."
              : "Kein Zugang passt zur Suche."}
          </p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Bezeichnung</th>
                  <th>Art</th>
                  <th>Benutzername</th>
                  <th>Gehört zu</th>
                  <th>Passwort</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {visible.map((a) => (
                  <tr key={a.id}>
                    <td>
                      <strong>{a.label}</strong>
                      {a.allowProbe ? (
                        <span className="badge ok" style={{ marginLeft: 8 }} title="Wird zum Auslesen des Geräts verwendet">
                          liest aus
                        </span>
                      ) : null}
                      {(a.assignmentCount ?? 0) > 0 && (
                        <span className="badge" style={{ marginLeft: 8 }}
                              title="Gilt zusätzlich für weitere Gerätekategorien/Subnetze/Geräte">
                          gilt für {a.assignmentCount} weitere
                        </span>
                      )}
                      {a.url && (
                        <div style={{ fontSize: "0.83rem" }}>
                          <a href={a.url} target="_blank" rel="noreferrer">{a.url}</a>
                        </div>
                      )}
                      {a.notes && <div className="muted" style={{ fontSize: "0.83rem" }}>{a.notes}</div>}
                    </td>
                    <td>{CATEGORY_LABEL[a.category] ?? a.category}</td>
                    <td className="mono">{a.username || "—"}</td>
                    <td>
                      {a.systemId ? (
                        <Link to={`/geraete/${a.systemId}`}>{systemName[a.systemId] ?? "unbekanntes Gerät"}</Link>
                      ) : (
                        <span className="muted">—</span>
                      )}
                    </td>
                    <td>
                      {!a.hasSecret ? (
                        <span className="muted">keins</span>
                      ) : secrets[a.id] !== undefined ? (
                        <code className="mono" style={{ whiteSpace: "pre-wrap", wordBreak: "break-all",
                                                        display: "block", maxWidth: 320, maxHeight: 160,
                                                        overflow: "auto" }}>
                          {secrets[a.id]}
                        </code>
                      ) : (
                        <button className="secondary small" onClick={() => void reveal(a.id)}>Anzeigen</button>
                      )}
                    </td>
                    <td style={{ whiteSpace: "nowrap", width: 1 }}>
                      <button className="secondary small" onClick={() => startEdit(a)}>Bearbeiten</button>{" "}
                      {a.category === "sshkey" && a.systemId && (
                        <>
                          <button className="secondary small"
                                  onClick={() => { setDeployingId(deployingId === a.id ? null : a.id); setDeployLoginId(""); }}>
                            Auf Gerät einspielen
                          </button>{" "}
                        </>
                      )}
                      <button className="danger small" onClick={() => void remove(a)}>Löschen</button>
                      {deployingId === a.id && (
                        <div className="row" style={{ marginTop: 8, flexWrap: "nowrap" }}>
                          <select style={{ width: "auto" }} value={deployLoginId}
                                  onChange={(e) => setDeployLoginId(e.target.value)}>
                            <option value="">— Zugang zum Einloggen wählen —</option>
                            {accounts
                              .filter((other) => other.systemId === a.systemId && other.id !== a.id && other.hasSecret)
                              .map((other) => (
                                <option key={other.id} value={other.id}>{other.label}</option>
                              ))}
                          </select>
                          <button className="secondary small" onClick={() => void deployKey(a)}
                                  disabled={busy || !deployLoginId}>
                            Einspielen
                          </button>
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
