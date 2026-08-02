import { useEffect, useState } from "react";
import { api, type Role, type User } from "../lib/api";
import { useAuth } from "../App";

const ROLE_LABEL: Record<Role, string> = {
  ADMIN: "Administrator",
  MEMBER: "Mitglied",
};

const ROLE_HELP: Record<Role, string> = {
  ADMIN: "Sieht und ändert alles, einschließlich gespeicherter Passwörter und Einstellungen.",
  MEMBER: "Liest die Dokumentation und nutzt den KI-Assistenten. Sieht keine Passwörter, ändert nichts.",
};

export default function UsersPage() {
  const { user: me } = useAuth();
  const [users, setUsers] = useState<User[]>([]);
  const [creating, setCreating] = useState(false);
  const [username, setUsername] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<Role>("MEMBER");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [editing, setEditing] = useState<User | null>(null);
  const [editName, setEditName] = useState("");
  const [editRole, setEditRole] = useState<Role>("MEMBER");
  const [editPassword, setEditPassword] = useState("");

  async function reload() {
    setUsers((await api.listUsers()).users);
  }

  useEffect(() => {
    reload()
      .catch((e) => setError(e instanceof Error ? e.message : String(e)))
      .finally(() => setLoading(false));
  }, []);

  function resetForm() {
    setCreating(false);
    setUsername("");
    setDisplayName("");
    setPassword("");
    setRole("MEMBER");
  }

  async function create() {
    setBusy(true);
    setError("");
    try {
      await api.createUser({ username: username.trim(), password, role, displayName: displayName.trim() });
      await reload();
      setNotice(`Benutzer „${username.trim()}“ angelegt.`);
      resetForm();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  function startEdit(user: User) {
    setNotice("");
    setError("");
    setCreating(false);
    setEditing(user);
    setEditName(user.displayName);
    setEditRole(user.role);
    setEditPassword("");
  }

  async function saveEdit() {
    if (!editing) return;
    setBusy(true);
    setError("");
    try {
      const body: { displayName?: string; role?: Role; newPassword?: string } = {
        displayName: editName,
        role: editRole,
      };
      if (editPassword) body.newPassword = editPassword;
      const r = await api.updateUser(editing.id, body);
      await reload();
      setNotice(
        r.changes.length > 0
          ? `„${editing.username}“: ${r.changes.join(", ")}.`
          : "Es gab nichts zu ändern.",
      );
      setEditing(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function remove(user: User) {
    if (!window.confirm(`Benutzer „${user.username}“ wirklich löschen?`)) return;
    setError("");
    try {
      await api.deleteUser(user.id);
      await reload();
      setNotice(`Benutzer „${user.username}“ gelöscht.`);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  const adminCount = users.filter((u) => u.role === "ADMIN").length;

  return (
    <>
      <div className="page-header">
        <div>
          <h1>Benutzer</h1>
          <p>
            Wer darf was? Administratoren verwalten Geräte, Zugänge und Einstellungen. Mitglieder
            lesen die Dokumentation und fragen den Assistenten — sie bekommen keine Passwörter zu
            sehen und können nichts ändern.
          </p>
        </div>
        {!creating && <button onClick={() => { setNotice(""); setCreating(true); }}>+ Benutzer anlegen</button>}
      </div>

      {error && <div className="notice error">{error}</div>}
      {notice && <div className="notice ok">{notice}</div>}

      {creating && (
        <div className="card">
          <h2>Neuer Benutzer</h2>
          <div className="grid cols-2">
            <div className="field">
              <label>Benutzername</label>
              <input autoFocus value={username} autoComplete="off"
                     onChange={(e) => setUsername(e.target.value)} />
            </div>
            <div className="field">
              <label>Anzeigename (optional)</label>
              <input placeholder="z. B. Anna" value={displayName}
                     onChange={(e) => setDisplayName(e.target.value)} />
            </div>
            <div className="field">
              <label>Passwort</label>
              <input type="password" autoComplete="new-password" value={password}
                     onChange={(e) => setPassword(e.target.value)} />
              <div className="field-hint">Mindestens 8 Zeichen.</div>
            </div>
            <div className="field">
              <label>Rolle</label>
              <select value={role} onChange={(e) => setRole(e.target.value as Role)}>
                <option value="MEMBER">{ROLE_LABEL.MEMBER}</option>
                <option value="ADMIN">{ROLE_LABEL.ADMIN}</option>
              </select>
              <div className="field-hint">{ROLE_HELP[role]}</div>
            </div>
          </div>
          <div className="row">
            <button onClick={() => void create()} disabled={busy || !username.trim() || password.length < 8}>
              {busy ? "Lege an…" : "Anlegen"}
            </button>
            <button className="secondary" onClick={resetForm}>Abbrechen</button>
          </div>
        </div>
      )}

      {editing && (
        <div className="card">
          <h2>„{editing.username}" bearbeiten</h2>
          <div className="grid cols-2">
            <div className="field">
              <label>Anzeigename</label>
              <input autoFocus value={editName} onChange={(e) => setEditName(e.target.value)} />
            </div>
            <div className="field">
              <label>Rolle</label>
              <select value={editRole} onChange={(e) => setEditRole(e.target.value as Role)}>
                <option value="MEMBER">{ROLE_LABEL.MEMBER}</option>
                <option value="ADMIN">{ROLE_LABEL.ADMIN}</option>
              </select>
              <div className="field-hint">{ROLE_HELP[editRole]}</div>
            </div>
            <div className="field" style={{ gridColumn: "1 / -1" }}>
              <label>Neues Passwort setzen (optional)</label>
              <input type="password" autoComplete="new-password" value={editPassword}
                     placeholder="leer lassen, um es nicht zu ändern"
                     onChange={(e) => setEditPassword(e.target.value)} />
              <div className="field-hint">
                Beim Zurücksetzen werden alle offenen Sitzungen dieses Benutzers beendet — er muss
                sich danach neu anmelden.
              </div>
            </div>
          </div>
          <div className="row">
            <button onClick={() => void saveEdit()} disabled={busy}>
              {busy ? "Speichere…" : "Speichern"}
            </button>
            <button className="secondary" onClick={() => setEditing(null)}>Abbrechen</button>
          </div>
        </div>
      )}

      <div className="card">
        {loading ? (
          <span className="spinner" />
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Benutzer</th>
                  <th>Rolle</th>
                  <th>Zwei-Faktor</th>
                  <th>Angelegt</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {users.map((u) => {
                  const isMe = u.id === me?.id;
                  const isLastAdmin = u.role === "ADMIN" && adminCount <= 1;
                  return (
                    <tr key={u.id}>
                      <td>
                        <strong>{u.displayName || u.username}</strong>
                        {u.displayName && u.displayName !== u.username && (
                          <div className="muted mono" style={{ fontSize: "0.8rem" }}>{u.username}</div>
                        )}
                        {isMe && <span className="badge" style={{ marginLeft: 8 }}>das bist du</span>}
                      </td>
                      <td>
                        <span className={`badge ${u.role === "ADMIN" ? "warn" : ""}`}>{ROLE_LABEL[u.role]}</span>
                      </td>
                      <td>
                        {u.totpEnabled ? (
                          <span className="badge ok">aktiv</span>
                        ) : (
                          <span className="muted">aus</span>
                        )}
                      </td>
                      <td className="muted">{new Date(u.createdAt).toLocaleDateString("de-DE")}</td>
                      <td style={{ width: 1, whiteSpace: "nowrap" }}>
                        <button className="secondary small" onClick={() => startEdit(u)}>Bearbeiten</button>{" "}
                        <button
                          className="danger small"
                          disabled={isMe || isLastAdmin}
                          title={
                            isMe
                              ? "Das eigene Konto lässt sich nicht löschen."
                              : isLastAdmin
                                ? "Der letzte Administrator lässt sich nicht löschen — sonst kommt niemand mehr an die Einstellungen."
                                : undefined
                          }
                          onClick={() => void remove(u)}
                        >
                          Löschen
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="card">
        <h2>Was die Rollen bedeuten</h2>
        <div className="table-wrap">
          <table>
            <tbody>
              <tr><th style={{ width: "30%" }}>{ROLE_LABEL.ADMIN}</th><td>{ROLE_HELP.ADMIN}</td></tr>
              <tr><th>{ROLE_LABEL.MEMBER}</th><td>{ROLE_HELP.MEMBER}</td></tr>
            </tbody>
          </table>
        </div>
        <p className="field-hint" style={{ marginTop: 12 }}>
          Ein Mitgliedskonto ist der sinnvolle Zugang für den Rest des Haushalts: die Notfall-Checkliste
          und der Assistent stehen zur Verfügung, das Router-Passwort aber nicht.
        </p>
      </div>
    </>
  );
}
