import { useState, type FormEvent } from "react";
import { ApiError, api } from "../lib/api";

export default function LoginPage({ onLoggedIn }: { onLoggedIn: () => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [needsCode, setNeedsCode] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      await api.login(username, password, totpCode);
      onLoggedIn();
    } catch (err) {
      // The backend answers 401 either way; the header distinguishes "wrong password" from
      // "password fine, second factor still needed" without the message giving that away.
      if (err instanceof ApiError && err.mfaRequired) {
        setNeedsCode(true);
        setTotpCode("");
      }
      setError(err instanceof Error ? err.message : "Anmeldung fehlgeschlagen.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="centered">
      <form className="card" onSubmit={submit}>
        <div className="brand" style={{ padding: "0 0 18px" }}>
          <span className="brand-mark">🧭</span>
          <div>
            <div className="brand-name">HomeAtlas</div>
            <div className="brand-sub">Dein Zuhause, dokumentiert</div>
          </div>
        </div>

        {error && <div className="notice error">{error}</div>}

        <div className="field">
          <label htmlFor="username">Benutzername</label>
          <input id="username" value={username} autoFocus autoComplete="username"
                 onChange={(e) => setUsername(e.target.value)} />
        </div>
        <div className="field">
          <label htmlFor="password">Passwort</label>
          <input id="password" type="password" value={password} autoComplete="current-password"
                 onChange={(e) => setPassword(e.target.value)} />
        </div>

        {needsCode && (
          <div className="field">
            <label htmlFor="totp">Code aus der Authenticator-App</label>
            <input
              id="totp"
              inputMode="numeric"
              autoComplete="one-time-code"
              maxLength={6}
              autoFocus
              placeholder="6-stellig"
              className="mono"
              style={{ letterSpacing: "0.4em", fontSize: "1.15rem" }}
              value={totpCode}
              onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, ""))}
            />
            <div className="field-hint">Der Code wechselt alle 30 Sekunden.</div>
          </div>
        )}

        <button
          type="submit"
          disabled={busy || !username || !password || (needsCode && totpCode.length < 6)}
          style={{ width: "100%" }}
        >
          {busy ? "Anmelden…" : "Anmelden"}
        </button>

        <p className="field-hint" style={{ marginTop: 16 }}>
          Beim allerersten Start steht das Passwort einmalig im Server-Protokoll:
          <br />
          <code className="mono">docker compose logs backend</code>
        </p>
      </form>
    </div>
  );
}
