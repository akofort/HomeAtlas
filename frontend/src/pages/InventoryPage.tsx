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

type SortKey = "name" | "ip" | "kind" | "location" | "status";

const STATUS_ORDER: Record<string, number> = { online: 0, unknown: 1, offline: 2 };

// Pads each octet so string comparison of the result orders IPv4 addresses numerically
// (plain string comparison would put "10" before "2"). Falls back to the raw value for
// anything that isn't a dotted-quad, which still sorts consistently even if not numerically.
function ipSortKey(ip: string): string {
  const parts = ip.split(".");
  if (parts.length !== 4 || !parts.every((p) => /^\d{1,3}$/.test(p))) return ip;
  return parts.map((p) => p.padStart(3, "0")).join(".");
}

export default function InventoryPage() {
  const { isAdmin } = useAuth();
  const [searchParams, setSearchParams] = useSearchParams();
  const [systems, setSystems] = useState<System[]>([]);
  const [kindLabels, setKindLabels] = useState<Record<string, string>>({});
  const [query, setQuery] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  // null = "unsorted" -- the order the API already returns (critical devices first, see
  // db.list_systems), which a column sort deliberately overrides until reset back to null.
  const [sort, setSort] = useState<{ key: SortKey; dir: "asc" | "desc" } | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [bulkBusy, setBulkBusy] = useState(false);

  function toggleSort(key: SortKey) {
    setSort((current) => {
      if (!current || current.key !== key) return { key, dir: "asc" };
      if (current.dir === "asc") return { key, dir: "desc" };
      return null;
    });
  }

  function sortIndicator(key: SortKey) {
    if (!sort || sort.key !== key) return "";
    return sort.dir === "asc" ? " ▲" : " ▼";
  }

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
    const filtered = systems.filter((s) => {
      if (kind && s.kind !== kind) return false;
      if (parentId && s.parentId !== parentId) return false;
      if (!needle) return true;
      return [s.name, s.hostname, s.ip, s.mac, s.vendor, s.model, s.location, s.purpose]
        .join(" ")
        .toLowerCase()
        .includes(needle);
    });
    if (!sort) return filtered; // natural order -- critical devices already first, see list_systems
    const sign = sort.dir === "asc" ? 1 : -1;
    const value = (s: System): string | number => {
      switch (sort.key) {
        case "ip": return ipSortKey(s.ip || "");
        case "kind": return kindLabels[s.kind] ?? s.kind;
        case "location": return s.location || "";
        case "status": return STATUS_ORDER[s.status] ?? 1;
        default: return s.name.toLowerCase();
      }
    };
    return [...filtered].sort((a, b) => {
      const va = value(a), vb = value(b);
      return va < vb ? -sign : va > vb ? sign : 0;
    });
  }, [systems, kind, parentId, query, sort, kindLabels]);

  function toggleSelected(id: string) {
    setSelected((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }

  function toggleSelectAllVisible() {
    setSelected((current) => {
      const allSelected = visible.length > 0 && visible.every((s) => current.has(s.id));
      if (allSelected) return new Set();
      return new Set(visible.map((s) => s.id));
    });
  }

  async function deleteSelected() {
    if (selected.size === 0) return;
    if (!window.confirm(`${selected.size} Gerät${selected.size === 1 ? "" : "e"} wirklich löschen?`)) return;
    setBulkBusy(true);
    const ids = [...selected];
    // allSettled, not all -- one failing delete (a stale row already gone server-side, a timeout)
    // must not stop the successful ones from being reflected in the UI.
    const results = await Promise.allSettled(ids.map((id) => api.deleteSystem(id)));
    const deletedIds = new Set(ids.filter((_, i) => results[i].status === "fulfilled"));
    if (deletedIds.size > 0) {
      setSystems((current) => current.filter((s) => !deletedIds.has(s.id)));
      setSelected((current) => {
        const next = new Set(current);
        deletedIds.forEach((id) => next.delete(id));
        return next;
      });
    }
    const failedCount = results.length - deletedIds.size;
    setError(failedCount > 0
      ? `${failedCount} Gerät${failedCount === 1 ? "" : "e"} konnten nicht gelöscht werden.`
      : "");
    setBulkBusy(false);
  }

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

        {isAdmin && selected.size > 0 && (
          <div className="row notice info" style={{ marginBottom: 14, alignItems: "center" }}>
            <strong>{selected.size}</strong> ausgewählt
            <button className="danger" style={{ marginLeft: "auto" }} disabled={bulkBusy}
                    onClick={() => void deleteSelected()}>
              {bulkBusy ? "Lösche…" : "Ausgewählte löschen"}
            </button>
            <button className="secondary" onClick={() => setSelected(new Set())} disabled={bulkBusy}>
              Auswahl aufheben
            </button>
          </div>
        )}

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
                  {isAdmin && (
                    <th style={{ width: 1 }}>
                      <input type="checkbox" style={{ width: "auto" }}
                             checked={visible.length > 0 && visible.every((s) => selected.has(s.id))}
                             onChange={toggleSelectAllVisible} />
                    </th>
                  )}
                  <th style={{ cursor: "pointer" }} onClick={() => toggleSort("name")}>Gerät{sortIndicator("name")}</th>
                  <th style={{ cursor: "pointer" }} onClick={() => toggleSort("ip")}>Adresse{sortIndicator("ip")}</th>
                  <th style={{ cursor: "pointer" }} onClick={() => toggleSort("kind")}>Art{sortIndicator("kind")}</th>
                  <th style={{ cursor: "pointer" }} onClick={() => toggleSort("location")}>Standort{sortIndicator("location")}</th>
                  <th style={{ cursor: "pointer" }} onClick={() => toggleSort("status")}>Zustand{sortIndicator("status")}</th>
                </tr>
              </thead>
              <tbody>
                {visible.map((s) => (
                  <tr key={s.id}>
                    {isAdmin && (
                      <td>
                        <input type="checkbox" style={{ width: "auto" }} checked={selected.has(s.id)}
                               onChange={() => toggleSelected(s.id)} />
                      </td>
                    )}
                    <td>
                      <Link to={`/geraete/${s.id}`}>
                        <strong>{s.name}</strong>
                      </Link>
                      {s.importance === "critical" && (
                        <span className="badge warn" style={{ marginLeft: 8 }}>kritisch</span>
                      )}
                      {!!s.errorCount && (
                        <span className="badge danger" style={{ marginLeft: 8 }}
                              title={`${s.errorCount} protokollierte(r) Fehler -- siehe Geräteseite`}>
                          ⚠ {s.errorCount}
                        </span>
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
