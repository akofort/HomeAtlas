import { useEffect, useRef, useState, type KeyboardEvent } from "react";
import { api, type Chat, type ChatMessage } from "../lib/api";
import Markdown from "../components/Markdown";

const SUGGESTIONS = [
  "Das Internet ist weg — was soll ich prüfen?",
  "Der Drucker taucht nicht mehr auf.",
  "Welche Geräte laufen gerade auf dem Server?",
  "Erkläre mir, was mein Router eigentlich macht.",
];

export default function ChatPage() {
  const [chats, setChats] = useState<Chat[]>([]);
  const [chatId, setChatId] = useState<string>("");
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [toolsUsed, setToolsUsed] = useState<string[]>([]);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    api.listChats().then((r) => {
      setChats(r.chats);
      if (r.chats.length > 0) setChatId(r.chats[0].id);
    });
  }, []);

  useEffect(() => {
    if (!chatId) {
      setMessages([]);
      return;
    }
    api.listMessages(chatId).then((r) => setMessages(r.messages)).catch((e) => setError(e.message));
  }, [chatId]);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [messages, busy]);

  async function ensureChat(): Promise<string> {
    if (chatId) return chatId;
    const { chat } = await api.createChat();
    setChats((c) => [chat, ...c]);
    setChatId(chat.id);
    return chat.id;
  }

  async function send(text: string) {
    const trimmed = text.trim();
    if (!trimmed || busy) return;
    setBusy(true);
    setError("");
    setToolsUsed([]);
    setInput("");
    // Optimistic echo so the question appears instantly; the id is replaced when the turn returns.
    const optimistic: ChatMessage = {
      id: `local-${Date.now()}`, chatId: chatId, role: "user",
      content: trimmed, createdAt: new Date().toISOString(),
    };
    setMessages((current) => [...current, optimistic]);
    try {
      const id = await ensureChat();
      const response = await api.sendMessage(id, trimmed);
      setMessages(await api.listMessages(id).then((r) => r.messages));
      setToolsUsed(response.toolsUsed);
      setChats(await api.listChats().then((r) => r.chats));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setMessages((current) => current.filter((m) => m.id !== optimistic.id));
      setInput(trimmed);
    } finally {
      setBusy(false);
    }
  }

  function onKeyDown(event: KeyboardEvent<HTMLTextAreaElement>) {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      void send(input);
    }
  }

  async function newChat() {
    const { chat } = await api.createChat();
    setChats((c) => [chat, ...c]);
    setChatId(chat.id);
    setMessages([]);
    setToolsUsed([]);
  }

  return (
    <>
      <div className="page-header">
        <div>
          <h1>KI-Assistent</h1>
          <p>
            Beschreibe in eigenen Worten, was nicht funktioniert. Der Assistent kennt deine Geräte und
            kann selbst nachmessen — pingen, Ports prüfen, Internetverbindung testen.
          </p>
        </div>
        <div className="row">
          {chats.length > 0 && (
            <select style={{ width: "auto" }} value={chatId} onChange={(e) => setChatId(e.target.value)}>
              {chats.map((c) => <option key={c.id} value={c.id}>{c.title}</option>)}
            </select>
          )}
          <button className="secondary" onClick={() => void newChat()}>Neue Unterhaltung</button>
        </div>
      </div>

      {error && <div className="notice error">{error}</div>}

      <div className="chat-layout">
        <div className="chat-scroll" ref={scrollRef}>
          {messages.length === 0 && !busy && (
            <div className="card">
              <h2>Womit kann ich helfen?</h2>
              <p className="muted">Zum Beispiel:</p>
              <div className="row">
                {SUGGESTIONS.map((s) => (
                  <button key={s} className="secondary small" onClick={() => void send(s)}>{s}</button>
                ))}
              </div>
            </div>
          )}

          {messages.map((m) => (
            <div key={m.id} className={`bubble ${m.role}`}>
              {m.role === "assistant" ? <Markdown>{m.content}</Markdown> : m.content}
            </div>
          ))}

          {busy && (
            <div className="bubble assistant">
              <span className="spinner" /> <span className="muted">Ich schaue nach…</span>
            </div>
          )}

          {!busy && toolsUsed.length > 0 && (
            <div className="tools-used">
              Dafür geprüft: {Array.from(new Set(toolsUsed)).join(", ")}
            </div>
          )}
        </div>

        <div className="chat-input">
          <textarea
            placeholder="Was funktioniert gerade nicht? (Enter zum Senden, Shift+Enter für eine neue Zeile)"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={onKeyDown}
            disabled={busy}
          />
          <button onClick={() => void send(input)} disabled={busy || !input.trim()}>Senden</button>
        </div>
      </div>
    </>
  );
}
