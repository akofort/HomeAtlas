import { useState } from "react";
import { api } from "../lib/api";
import { useAuth } from "../App";

/** Erzwungene Ersteinrichtung der Zwei-Faktor-Anmeldung. Zeigt App.tsx an, solange
 *  `user.totpEnabled` falsch ist -- kein anderer Teil der App ist bis dahin erreichbar (das
 *  Backend setzt das durch, dies hier ist nur die dazu passende Oberfläche). Abmelden bleibt der
 *  einzige Ausweg, damit niemand technisch ausgesperrt ist, nur weil das Handy gerade fehlt. */
export default function MfaEnrollPage({ onDone }: { onDone: () => void }) {
  const { user, logout } = useAuth();
  const [setup, setSetup] = useState<{ secret: string; uri: string; qrSvg: string } | null>(null);
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function start() {
    setBusy(true);
    setError("");
    try {
      setSetup(await api.mfaSetup());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function confirm() {
    setBusy(true);
    setError("");
    try {
      await api.mfaConfirm(code);
      onDone();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="centered">
      <div className="card" style={{ maxWidth: 440 }}>
        <div className="brand" style={{ padding: "0 0 18px" }}>
          <span className="brand-mark">🔐</span>
          <div>
            <div className="brand-name">Zwei-Faktor-Anmeldung einrichten</div>
            <div className="brand-sub">Angemeldet als {user?.displayName || user?.username}</div>
          </div>
        </div>

        <p className="muted">
          Ab jetzt ist ein zweiter Faktor Pflicht — zusätzlich zum Passwort ein Code aus einer
          Authenticator-App (Aegis, 2FAS, Google Authenticator, 1Password …). Ohne Einrichtung geht
          es hier nicht weiter; ein Administrator kann sie bei Bedarf zurücksetzen, falls das Gerät
          mit der App verloren geht.
        </p>

        {error && <div className="notice error">{error}</div>}

        {setup ? (
          <>
            <p className="muted">
              <strong>1.</strong> QR-Code in der App scannen — oder den Schlüssel von Hand eintippen.
            </p>
            {setup.qrSvg ? (
              <div
                style={{ background: "#fff", padding: 10, borderRadius: 10, display: "inline-block" }}
                dangerouslySetInnerHTML={{ __html: setup.qrSvg }}
              />
            ) : (
              <div className="notice info">
                QR-Code konnte nicht erzeugt werden — bitte den Schlüssel unten von Hand eintragen.
              </div>
            )}
            <div className="field" style={{ marginTop: 12 }}>
              <label>Schlüssel zum Abtippen</label>
              <code className="mono" style={{ display: "block", wordBreak: "break-all", background: "var(--bg)", padding: "8px 10px", borderRadius: 8 }}>
                {setup.secret}
              </code>
            </div>
            <p className="muted"><strong>2.</strong> Zur Bestätigung den aktuellen Code eingeben:</p>
            <div className="field" style={{ maxWidth: 220 }}>
              <input
                inputMode="numeric"
                autoComplete="one-time-code"
                maxLength={6}
                autoFocus
                placeholder="6-stellig"
                className="mono"
                style={{ letterSpacing: "0.4em", fontSize: "1.15rem" }}
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
              />
            </div>
            <button onClick={() => void confirm()} disabled={busy || code.length < 6} style={{ width: "100%" }}>
              {busy ? "Prüfe…" : "Aktivieren"}
            </button>
          </>
        ) : (
          <button onClick={() => void start()} disabled={busy} style={{ width: "100%" }}>
            {busy ? "Erzeuge…" : "Einrichtung starten"}
          </button>
        )}

        <button className="secondary small" style={{ marginTop: 16 }} onClick={() => void logout()}>
          Abmelden
        </button>
      </div>
    </div>
  );
}
