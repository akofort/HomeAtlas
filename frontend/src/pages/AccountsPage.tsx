import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api, type Account, type System } from "../lib/api";

const CATEGORIES: [string, string][] = [
  ["contract", "Vertrag / Kundenkonto"],
  ["login", "Anmeldung an Gerät oder Dienst"],
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
  url: string;
  notes: string;
}

const emptyDraft = (): Draft => ({
  id: null, systemId: "", label: "", category: "contract",
  username: "", secret: "", url: "", notes: "",
});

export default function AccountsPage() {
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [systems, setSystems] = useState<System[]>([]);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [secrets, setSecrets] = useState<Record<string, string>>({});
  const [query, setQuery] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);

  async function reload() {
    const [a, s] = await Promise.all([api.listAccounts(), api.listSystems()]);
    setAccounts(a.accounts);
    setSystems(s.systems);
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
    setDraft({
      id: account.id,
      systemId: account.systemId ?? "",
      label: account.label,
      category: account.category,
      username: account.username,
      // Never prefilled: the plaintext is fetched only on explicit "Anzeigen", and a blank field
      // means "leave the stored password alone" (see the backend's update_account).
      secret: "",
      url: account.url,
      notes: account.notes,
    });
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
        url: draft.url,
        notes: draft.notes,
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
        {!draft && <button onClick={() => { setNotice(""); setDraft(emptyDraft()); }}>+ Neuer Zugang</button>}
      </div>

      {error && <div className="notice error">{error}</div>}
      {notice && <div className="notice ok">{notice}</div>}

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
              <label>Benutzername / Kundennummer</label>
              <input value={draft.username} autoComplete="off"
                     onChange={(e) => setDraft({ ...draft, username: e.target.value })} />
            </div>
            <div className="field">
              <label>Passwort</label>
              <input type="password" autoComplete="new-password" value={draft.secret}
                     placeholder={draft.id ? "unverändert lassen" : ""}
                     onChange={(e) => setDraft({ ...draft, secret: e.target.value })} />
              <div className="field-hint">
                {draft.id
                  ? "Leer lassen, um das gespeicherte Passwort beizubehalten."
                  : "Wird verschlüsselt gespeichert."}
              </div>
            </div>
            <div className="field">
              <label>Adresse (optional)</label>
              <input placeholder="https://…" value={draft.url}
                     onChange={(e) => setDraft({ ...draft, url: e.target.value })} />
            </div>
            <div className="field" style={{ gridColumn: "1 / -1" }}>
              <label>Notiz (optional)</label>
              <input placeholder="z. B. Hotline 0800 …, Vertrag läuft bis …" value={draft.notes}
                     onChange={(e) => setDraft({ ...draft, notes: e.target.value })} />
            </div>
          </div>
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
                        <code className="mono">{secrets[a.id]}</code>
                      ) : (
                        <button className="secondary small" onClick={() => void reveal(a.id)}>Anzeigen</button>
                      )}
                    </td>
                    <td style={{ whiteSpace: "nowrap", width: 1 }}>
                      <button className="secondary small" onClick={() => startEdit(a)}>Bearbeiten</button>{" "}
                      <button className="danger small" onClick={() => void remove(a)}>Löschen</button>
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
