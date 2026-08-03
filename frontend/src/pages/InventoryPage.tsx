import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, type System } from "../lib/api";
import { useAuth } from "../App";
import { KindIcon } from "../lib/icons";

const STATUS_LABEL: Record<string, string> = {
  online: "erreichbar",
  offline: "nicht erreichbar",
  unknown: "unbekannt",
};

export default function InventoryPage() {
  const { isAdmin } = useAuth();
  const [searchParams, setSearchParams] = useSearchParams();
  const [systems, setSystems] = useState<System[]>([]);
  const [kindLabels, setKindLabels] = useState<Record<string, string>>({});
  const [query, setQuery] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  const kind = searchParams.get("kind") ?? "";
  const parentId = searchParams.get("parentId") ?? "";

  useEffect(() => {
    setLoading(true);
    api
      .listSystems()
      .then((r) => {
        setSystems(r.systems);
        setKindLabels(r.kindLabels);
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  const visible = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return systems.filter((s) => {
      if (kind && s.kind !== kind) return false;
      if (parentId && s.parentId !== parentId) return false;
      if (!needle) return true;
      return [s.name, s.hostname, s.ip, s.mac, s.vendor, s.model, s.location, s.purpose]
        .join(" ")
        .toLowerCase()
        .includes(needle);
    });
  }, [systems, kind, parentId, query]);

  const parentSystem = useMemo(
    () => (parentId ? systems.find((s) => s.id === parentId) : undefined),
    [systems, parentId],
  );

  const kinds = useMemo(
    () => Array.from(new Set(systems.map((s) => s.kind))).sort(),
    [systems],
  );

  async function addSystem() {
    const name = window.prompt("Wie soll das neue Gerät heißen?");
    if (!name?.trim()) return;
    try {
      const { system } = await api.createSystem({ name: name.trim(), kind: "other" });
      setSystems((current) => [system, ...current]);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <>
      <div className="page-header">
        <div>
          <h1>Geräte</h1>
          <p>
            Alles, was im Heimnetz gefunden oder von Hand eingetragen wurde. Selbst gepflegte Angaben
            bleiben bei künftigen Scans erhalten.
          </p>
        </div>
        {isAdmin && <button onClick={() => void addSystem()}>+ Gerät anlegen</button>}
      </div>

      {error && <div className="notice error">{error}</div>}

      {parentId && (
        <div className="notice info">
          Zeigt Container und VMs auf <strong>{parentSystem?.name ?? "diesem Host"}</strong>.{" "}
          <button className="secondary" style={{ marginLeft: 8 }} onClick={() => setSearchParams({})}>
            Filter aufheben
          </button>
        </div>
      )}

      <div className="card">
        <div className="row" style={{ marginBottom: 14 }}>
          <input
            style={{ flex: 1, minWidth: 220 }}
            placeholder="Suchen nach Name, IP, Hersteller, Raum …"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          <select
            style={{ width: "auto" }}
            value={kind}
            onChange={(e) => setSearchParams(e.target.value ? { kind: e.target.value } : {})}
          >
            <option value="">Alle Kategorien</option>
            {kinds.map((k) => (
              <option key={k} value={k}>
                {kindLabels[k] ?? k}
              </option>
            ))}
          </select>
        </div>

        {loading ? (
          <span className="spinner" />
        ) : visible.length === 0 ? (
          <p className="muted">
            Keine Geräte gefunden.{" "}
            {systems.length === 0 && isAdmin && (
              <>
                Starte einen <Link to="/scan">Netzwerk-Scan</Link>, um das Heimnetz automatisch zu erfassen.
              </>
            )}
          </p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Gerät</th>
                  <th>Adresse</th>
                  <th>Art</th>
                  <th>Standort</th>
                  <th>Zustand</th>
                </tr>
              </thead>
              <tbody>
                {visible.map((s) => (
                  <tr key={s.id}>
                    <td>
                      <Link to={`/geraete/${s.id}`}>
                        <strong>{s.name}</strong>
                      </Link>
                      {s.importance === "critical" && (
                        <span className="badge warn" style={{ marginLeft: 8 }}>kritisch</span>
                      )}
                      {(s.tags ?? []).some((t) => t.toLowerCase().includes("poe")) && (
                        <span className="badge warn" style={{ marginLeft: 8 }}
                              title="Funktioniert ohne PoE-fähigen Switch oder Injector nicht">
                          ⚡ PoE
                        </span>
                      )}
                      {s.purpose && (
                        <div className="muted" style={{ fontSize: "0.83rem" }}>{s.purpose}</div>
                      )}
                    </td>
                    <td className="mono">
                      {s.ip || "—"}
                      {s.hostname && <div className="muted" style={{ fontSize: "0.8rem" }}>{s.hostname.split(".")[0]}</div>}
                    </td>
                    <td>
                      <span className="row" style={{ gap: 6, flexWrap: "nowrap" }}>
                        <KindIcon kind={s.kind} className="muted" />
                        {kindLabels[s.kind] ?? s.kind}
                      </span>
                    </td>
                    <td>{s.location || "—"}</td>
                    <td>
                      <span className={`badge ${s.status === "online" ? "ok" : s.status === "offline" ? "danger" : ""}`}>
                        {STATUS_LABEL[s.status] ?? s.status}
                      </span>
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
