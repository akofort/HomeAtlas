import { useEffect, useRef, useState } from "react";
import { Terminal as XTerm } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";

type Status = "connecting" | "connected" | "closed" | "error";

/** Embeds an interactive terminal wired to a WebSocket console route (SSH or `docker exec`).
 *  Framing: binary WS frames carry raw terminal bytes unmodified in both directions; text frames
 *  are JSON control messages -- currently only `{"type":"resize",...}` sent by us and
 *  `{"type":"error"|"exit",...}` sent by the backend. Matches backend/app/main.py's
 *  `_relay_terminal`. */
export default function Terminal({ wsUrl, onClose }: { wsUrl: string; onClose?: () => void }) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [status, setStatus] = useState<Status>("connecting");
  const [message, setMessage] = useState("");

  useEffect(() => {
    const term = new XTerm({
      cursorBlink: true,
      fontFamily: "ui-monospace, Menlo, Consolas, monospace",
      fontSize: 13,
      theme: { background: "#00000000" },
    });
    const fitAddon = new FitAddon();
    term.loadAddon(fitAddon);
    if (containerRef.current) term.open(containerRef.current);

    const ws = new WebSocket(wsUrl);
    ws.binaryType = "arraybuffer";

    ws.onopen = () => {
      setStatus("connected");
      fitAddon.fit();
      ws.send(JSON.stringify({ type: "resize", cols: term.cols, rows: term.rows }));
    };
    ws.onmessage = (event) => {
      if (typeof event.data === "string") {
        try {
          const control = JSON.parse(event.data);
          if (control.type === "error") {
            setStatus("error");
            setMessage(control.message || "Fehler in der Sitzung.");
            term.writeln(`\r\n\x1b[31m${control.message || "Fehler in der Sitzung."}\x1b[0m`);
          }
        } catch {
          /* ignore malformed control frames */
        }
        return;
      }
      term.write(new Uint8Array(event.data));
    };
    ws.onclose = () => {
      setStatus((current) => (current === "error" ? current : "closed"));
      term.writeln("\r\n\x1b[90m— Verbindung beendet —\x1b[0m");
    };
    ws.onerror = () => {
      setStatus("error");
      setMessage("Verbindung fehlgeschlagen.");
    };

    const dataDisposable = term.onData((data) => {
      if (ws.readyState === WebSocket.OPEN) ws.send(new TextEncoder().encode(data));
    });
    const resizeDisposable = term.onResize(({ cols, rows }) => {
      if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: "resize", cols, rows }));
    });

    const observer = new ResizeObserver(() => fitAddon.fit());
    if (containerRef.current) observer.observe(containerRef.current);

    return () => {
      observer.disconnect();
      dataDisposable.dispose();
      resizeDisposable.dispose();
      ws.close();
      term.dispose();
    };
  }, [wsUrl]);

  return (
    <div>
      <div className="row" style={{ marginBottom: 8, justifyContent: "space-between" }}>
        <span className={`badge ${status === "connected" ? "ok" : status === "error" ? "danger" : ""}`}>
          {status === "connecting" && "verbinde…"}
          {status === "connected" && "verbunden"}
          {status === "closed" && "getrennt"}
          {status === "error" && (message || "Fehler")}
        </span>
        {onClose && (
          <button className="secondary small" onClick={onClose}>Schließen</button>
        )}
      </div>
      <div
        ref={containerRef}
        style={{ height: 420, background: "#0b1120", borderRadius: 10, padding: 8 }}
      />
    </div>
  );
}
