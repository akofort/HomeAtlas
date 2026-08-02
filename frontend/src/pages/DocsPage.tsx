import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, type DocPage } from "../lib/api";
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

  useEffect(() => {
    api.listDocs().then((r) => setPages(r.pages)).catch((e) => setError(e.message));
  }, []);

  useEffect(() => {
    if (!slug) {
      setPage(null);
      return;
    }
    setEditing(false);
    api.getDoc(slug).then((r) => setPage(r.page)).catch((e) => setError(e.message));
  }, [slug]);

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

              {editing ? (
                <>
                  <div className="notice info">
                    Sobald du eine Seite von Hand speicherst, wird sie beim nächsten automatischen Lauf
                    nicht mehr überschrieben.
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
