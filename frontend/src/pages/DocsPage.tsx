import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, type DocPage, type DocVersion } from "../lib/api";
import { useAuth } from "../App";
import Markdown from "../components/Markdown";

export default function DocsPage() {
  const { slug } = useParams();
  const navigate = useNavigate();
  const { isAdmin } = useAuth();
  const [pages, setPages] = useState<Omit<DocPage, "bodyMd">[]>([]);
  const [page, setPage] = useState<DocPage | null>(null);
  const [draft, setDraft] = useState("");
  const [editing, setEditing] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [versions, setVersions] = useState<DocVersion[] | null>(null);
  const [preview, setPreview] = useState<DocVersion | null>(null);
  const [manualDraft, setManualDraft] = useState<string | null>(null);

  useEffect(() => {
    api.listDocs().then((r) => setPages(r.pages)).catch((e) => setError(e.message));
  }, []);

  useEffect(() => {
    if (!slug) {
      setPage(null);
      return;
    }
    setEditing(false);
    setVersions(null);
    setPreview(null);
    setManualDraft(null);
    api.getDoc(slug).then((r) => setPage(r.page)).catch((e) => setError(e.message));
  }, [slug]);

  async function toggleVersions() {
    if (!slug) return;
    if (versions) {
      setVersions(null);
      setPreview(null);
      return;
    }
    try {
      setVersions((await api.listDocVersions(slug)).versions);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  async function showVersion(version: DocVersion) {
    if (!slug) return;
    try {
      setPreview((await api.getDocVersion(slug, version.id)).version);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  async function restoreVersion(version: DocVersion) {
    if (!slug) return;
    const when = new Date(version.createdAt).toLocaleString("de-DE");
    if (!window.confirm(`Stand vom ${when} wiederherstellen? Der aktuelle Text wird vorher als Version gesichert.`)) return;
    setBusy(true);
    try {
      setPage((await api.restoreDocVersion(slug, version.id)).page);
      setVersions((await api.listDocVersions(slug)).versions);
      setPreview(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function regenerate() {
    setBusy(true);
    setError("");
    try {
      await api.generateDocs(true);
      const list = await api.listDocs();
      setPages(list.pages);
      if (slug) setPage((await api.getDoc(slug)).page);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function save() {
    if (!slug) return;
    setBusy(true);
    try {
      setPage((await api.saveDoc(slug, draft)).page);
      setEditing(false);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function saveManual() {
    if (!slug || manualDraft === null) return;
    setBusy(true);
    try {
      setPage((await api.saveDocManual(slug, manualDraft)).page);
      setManualDraft(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function resetPage() {
    if (!slug) return;
    if (!window.confirm("Diese Seite neu erzeugen? Deine eigenen Änderungen an dieser Seite gehen dabei verloren.")) return;
    setBusy(true);
    try {
      setPage((await api.resetDoc(slug)).page);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <div className="page-header">
        <div>
          <h1>Dokumentation</h1>
          <p>
            Nach Themen sortiert und in verständlicher Sprache — erzeugt aus dem, was HomeAtlas im
            Netzwerk gefunden hat. Jede Seite lässt sich von Hand überarbeiten.
          </p>
        </div>
        {isAdmin && (
          <button className="secondary" onClick={() => void regenerate()} disabled={busy}>
            {busy ? "Erzeuge…" : "Alles neu erzeugen"}
          </button>
        )}
      </div>

      {error && <div className="notice error">{error}</div>}

      <div style={{ display: "flex", gap: 20, alignItems: "flex-start", flexWrap: "wrap" }}>
        <div className="card" style={{ flex: "0 0 260px", minWidth: 240 }}>
          <h2 style={{ fontSize: "0.9rem", textTransform: "uppercase", letterSpacing: "0.04em", color: "var(--text-muted)" }}>
            Kapitel
          </h2>
          {pages.length === 0 ? (
            <p className="muted">Noch keine Kapitel. Führe einen Netzwerk-Scan durch.</p>
          ) : (
            pages.map((p) => (
              <Link
                key={p.slug}
                to={`/dokumentation/${p.slug}`}
                className="nav-link"
                style={{
                  background: p.slug === slug ? "var(--bg-hover)" : undefined,
                  color: p.slug === slug ? "var(--text)" : undefined,
                }}
              >
                {p.title}
              </Link>
            ))
          )}
        </div>

        <div style={{ flex: 1, minWidth: 300 }}>
          {!slug ? (
            <div className="card">
              <h2>Wähle links ein Kapitel</h2>
              <p className="muted">
                Wenn gerade etwas nicht funktioniert, ist <strong>„Wenn etwas nicht funktioniert"</strong> der
                richtige Einstieg — dort steht eine Checkliste, der man auch unter Zeitdruck folgen kann.
              </p>
              {pages.some((p) => p.slug === "notfall") && (
                <button onClick={() => navigate("/dokumentation/notfall")}>Zur Notfall-Checkliste</button>
              )}
            </div>
          ) : !page ? (
            <span className="spinner" />
          ) : (
            <div className="card">
              <div className="row" style={{ justifyContent: "space-between", marginBottom: 14 }}>
                <h2 style={{ margin: 0 }}>{page.title}</h2>
                {isAdmin && (
                  <div className="row">
                    {page.generated === 0 && <span className="badge warn">von Hand bearbeitet</span>}
                    {!editing ? (
                      <>
                        <button className="secondary small" onClick={() => void toggleVersions()}>
                          {versions ? "Verlauf schließen" : "Verlauf"}
                        </button>
                        <button className="secondary small" onClick={() => { setDraft(page.bodyMd); setEditing(true); }}>
                          Bearbeiten
                        </button>
                        {page.generated === 0 && (
                          <button className="secondary small" onClick={() => void resetPage()} disabled={busy}>
                            Neu erzeugen
                          </button>
                        )}
                      </>
                    ) : (
                      <>
                        <button className="small" onClick={() => void save()} disabled={busy}>Speichern</button>
                        <button className="secondary small" onClick={() => setEditing(false)}>Abbrechen</button>
                      </>
                    )}
                  </div>
                )}
              </div>

              {versions && (
                <div className="card" style={{ background: "var(--bg)" }}>
                  <h3 style={{ marginTop: 0 }}>Verlauf dieser Seite</h3>
                  {versions.length === 0 ? (
                    <p className="muted" style={{ marginBottom: 0 }}>
                      Noch keine früheren Stände. Ab der ersten Änderung wird jeder vorherige Text
                      hier gesichert.
                    </p>
                  ) : (
                    <div className="table-wrap">
                      <table>
                        <thead>
                          <tr><th>Zeitpunkt</th><th>Anlass</th><th>Umfang</th><th /></tr>
                        </thead>
                        <tbody>
                          {versions.map((v) => (
                            <tr key={v.id}>
                              <td>{new Date(v.createdAt).toLocaleString("de-DE")}</td>
                              <td className="muted">{v.reason}</td>
                              <td className="muted">{Math.round(v.size / 100) / 10} kB</td>
                              <td style={{ whiteSpace: "nowrap", width: 1 }}>
                                <button className="secondary small" onClick={() => void showVersion(v)}>Ansehen</button>{" "}
                                <button className="secondary small" disabled={busy}
                                        onClick={() => void restoreVersion(v)}>Wiederherstellen</button>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              )}

              {!preview && !editing && (manualDraft !== null || page.manualMd?.trim() || isAdmin) && (
                <div
                  className="card"
                  style={{
                    background: "var(--bg)",
                    borderLeft: "3px solid var(--accent-strong)",
                    marginBottom: 20,
                  }}
                >
                  <div className="row" style={{ justifyContent: "space-between", marginBottom: 10 }}>
                    <h3 style={{ margin: 0 }}>Eigene Notizen</h3>
                    {isAdmin && (
                      manualDraft === null ? (
                        <button className="secondary small" onClick={() => setManualDraft(page.manualMd ?? "")}>
                          {page.manualMd?.trim() ? "Bearbeiten" : "Notiz hinzufügen"}
                        </button>
                      ) : (
                        <div className="row">
                          <button className="small" onClick={() => void saveManual()} disabled={busy}>
                            Speichern
                          </button>
                          <button className="secondary small" onClick={() => setManualDraft(null)}>
                            Abbrechen
                          </button>
                        </div>
                      )
                    )}
                  </div>

                  {manualDraft !== null ? (
                    <>
                      <div className="notice info">
                        Dieser Teil gehört dir. Er wird von HomeAtlas <strong>nie</strong> automatisch
                        geändert oder überschrieben — auch nicht beim Neuerzeugen der Dokumentation.
                        Alles darunter bleibt dagegen automatisch aktuell.
                      </div>
                      <textarea
                        style={{ minHeight: 220 }}
                        autoFocus
                        placeholder={
                          "z. B.\n\n- Sicherung für den Serverschrank: Keller, Kasten links, F3\n" +
                          "- Nach Stromausfall braucht der Switch ~5 Minuten, bevor WLAN wieder geht\n" +
                          "- Wartungsvertrag Heizung: Firma Meier, 0123 456789"
                        }
                        value={manualDraft}
                        onChange={(e) => setManualDraft(e.target.value)}
                      />
                    </>
                  ) : page.manualMd?.trim() ? (
                    <Markdown>{page.manualMd}</Markdown>
                  ) : (
                    <p className="muted" style={{ margin: 0 }}>
                      Noch keine eigenen Notizen zu diesem Kapitel. Was hier steht, bleibt dauerhaft
                      erhalten — Sicherungskästen, Standorte, Ansprechpartner, Eigenheiten, die kein
                      Scan finden kann.
                    </p>
                  )}
                </div>
              )}

              {preview ? (
                <>
                  <div className="notice info">
                    Alter Stand vom <strong>{new Date(preview.createdAt).toLocaleString("de-DE")}</strong> ({preview.reason}).
                    Dies ist nur eine Ansicht — die Seite selbst ist unverändert.{" "}
                    <button className="secondary small" onClick={() => setPreview(null)}>Zurück zum aktuellen Stand</button>
                  </div>
                  {preview.manualMd?.trim() && (
                    <div className="card" style={{ background: "var(--bg)", borderLeft: "3px solid var(--border)" }}>
                      <h3 style={{ marginTop: 0 }}>Eigene Notizen (damaliger Stand)</h3>
                      <Markdown>{preview.manualMd}</Markdown>
                    </div>
                  )}
                  <Markdown>{preview.bodyMd ?? ""}</Markdown>
                </>
              ) : editing ? (
                <>
                  <div className="notice info">
                    Du bearbeitest hier den <strong>automatisch erzeugten</strong> Teil. Sobald du ihn
                    von Hand speicherst, wird die ganze Seite beim nächsten Lauf nicht mehr
                    aktualisiert — Gerätetabellen bleiben dann auf diesem Stand stehen. Für dauerhafte
                    Ergänzungen sind meist die <strong>eigenen Notizen</strong> die bessere Wahl: die
                    bleiben erhalten, während der Rest aktuell bleibt.
                  </div>
                  <textarea style={{ minHeight: 480 }} value={draft} onChange={(e) => setDraft(e.target.value)} />
                </>
              ) : (
                <Markdown>{page.bodyMd}</Markdown>
              )}
            </div>
          )}
        </div>
      </div>
    </>
  );
}
