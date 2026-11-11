import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, ApiError, streamNdjson } from "../api/client";
import { Card, ErrorText, useLoad } from "../components/common";
import { dateTime } from "../format";

interface Status { enabled: boolean; model: string | null; reason: string | null }
interface ConversationSummary { id: number; title: string; user_turns: number; updated_at: string }
interface StoredMessage { role: "user" | "assistant"; text: string; tools: string[] }
interface Conversation extends ConversationSummary { messages: StoredMessage[] }

interface Bubble {
  role: "user" | "assistant";
  text: string;
  tools: { name: string; ok?: boolean }[];
  actions: { id: number; ip: string }[];
  error?: string;
}

const TOOL_LABELS: Record<string, string> = {
  search_alerts: "searched alerts", get_alert: "read the alert", top_attackers: "looked up top attackers",
  list_blocks: "listed blocks", get_case: "read the case", metrics_summary: "read the metrics",
  get_playbook: "read the playbook", propose_block: "proposed a block",
};

const SUGGESTIONS = [
  "Who were the top attackers in the last 24 hours?",
  "Summarise today's critical and high alerts.",
  "What's our false-positive rate this week?",
];

/** Show the assistant's text with alert/action ids turned into links. Never renders HTML. */
function Linked({ text }: { text: string }) {
  const parts: ReactNode[] = [];
  const re = /(alert|action|case) #(\d{1,12})/gi;
  let last = 0;
  for (const m of text.matchAll(re)) {
    const i = m.index ?? 0;
    parts.push(text.slice(last, i));
    const kind = m[1].toLowerCase();
    const to = kind === "alert" ? `/alerts/${m[2]}` : kind === "case" ? `/cases/${m[2]}` : "/actions";
    parts.push(<Link key={i} to={to}>{m[0]}</Link>);
    last = i + m[0].length;
  }
  parts.push(text.slice(last));
  return <>{parts}</>;
}

export default function Assistant() {
  const [params, setParams] = useSearchParams();
  const { data: status } = useLoad(() => api<Status>("/assistant/status"), []);
  const { data: history, reload: reloadHistory } = useLoad(
    () => api<ConversationSummary[]>("/assistant/conversations"), []);
  const [conversationId, setConversationId] = useState<number | null>(null);
  const [bubbles, setBubbles] = useState<Bubble[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const abort = useRef<AbortController | null>(null);
  const bottom = useRef<HTMLDivElement>(null);

  // "Explain this alert" from an alert page: /assistant?alert=12
  useEffect(() => {
    const alertId = params.get("alert");
    if (alertId && /^\d{1,12}$/.test(alertId) && status?.enabled) {
      setParams({}, { replace: true });
      void send(`Explain alert #${alertId}: why did the model flag it, is it likely a real attack, and what should I do?`, null);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [status?.enabled]);

  useEffect(() => () => { abort.current?.abort(); }, []);
  // Braces matter: newer browsers return a Promise from scrollIntoView, and an effect
  // must return nothing or a cleanup function.
  useEffect(() => { bottom.current?.scrollIntoView({ block: "end" }); }, [bubbles]);

  async function open(id: number) {
    if (busy) return;
    let conv: Conversation;
    try {
      conv = await api<Conversation>(`/assistant/conversations/${id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      return;
    }
    setConversationId(conv.id);
    setBubbles(conv.messages.map((m) => ({ role: m.role, text: m.text, actions: [],
      tools: m.tools.map((name) => ({ name, ok: true })) })));
    setError(null);
  }

  function newChat() {
    if (busy) return;
    setConversationId(null);
    setBubbles([]);
    setError(null);
  }

  function update(fn: (b: Bubble) => Bubble) {
    setBubbles((bs) => [...bs.slice(0, -1), fn(bs[bs.length - 1])]);
  }

  async function send(message: string, convId: number | null = conversationId) {
    const text = message.trim();
    if (!text || busy) return;
    setBusy(true);
    setError(null);
    setInput("");
    setBubbles((bs) => [...bs, { role: "user", text, tools: [], actions: [] },
      { role: "assistant", text: "", tools: [], actions: [] }]);
    abort.current = new AbortController();
    try {
      await streamNdjson("/assistant/chat", { message: text, ...(convId ? { conversation_id: convId } : {}) }, (e) => {
        switch (e.type) {
          case "conversation":
            setConversationId(Number(e.conversation_id));
            break;
          case "text":
            update((b) => ({ ...b, text: b.text + String(e.text ?? "") }));
            break;
          case "tool":
            update((b) => ({ ...b, tools: [...b.tools, { name: String(e.name) }] }));
            break;
          case "tool_result":
            update((b) => {
              const tools = [...b.tools];
              const i = tools.map((t) => t.name).lastIndexOf(String(e.name));
              if (i >= 0) tools[i] = { ...tools[i], ok: Boolean(e.ok) };
              return { ...b, tools };
            });
            break;
          case "action_proposed":
            update((b) => ({ ...b, actions: [...b.actions, { id: Number(e.action_id), ip: String(e.ip) }] }));
            break;
          case "error":
            update((b) => ({ ...b, error: String(e.message ?? "error") }));
            break;
        }
      }, abort.current.signal);
    } catch (err) {
      if (!(err instanceof DOMException && err.name === "AbortError")) {
        setError(err instanceof ApiError ? err.message : "Can't reach the SOC API");
        // keep a partial reply (and any proposal notice); drop only an empty bubble
        setBubbles((bs) => {
          const last = bs[bs.length - 1];
          return last && !last.text && last.actions.length === 0 ? bs.slice(0, -1) : bs;
        });
      }
    } finally {
      setBusy(false);
      void reloadHistory();
    }
  }

  function submit(e: FormEvent) {
    e.preventDefault();
    void send(input);
  }

  if (status && !status.enabled) {
    return (
      <>
        <h1>Assistant</h1>
        <Card>
          <h2>The assistant is switched off</h2>
          <p>{status.reason}</p>
          <p className="muted">Everything else in the SOC works without it. See docs/soc.md to turn it on.</p>
        </Card>
      </>
    );
  }

  return (
    <>
      <h1>Assistant</h1>
      <div className="grid cols-chat">
        <div className="card chat">
          <div className="chat-log" aria-live="polite">
            {bubbles.length === 0 && (
              <div className="muted">
                <p>Ask about alerts, attackers, blocks, cases or metrics, or open an alert and choose
                  “Explain this alert”. The assistant reads SOC data through fixed tools. It can only
                  <b> propose</b> a block: you confirm it on the Actions page.</p>
                <div className="row-actions">
                  {SUGGESTIONS.map((s) => <button key={s} onClick={() => void send(s)} disabled={busy}>{s}</button>)}
                </div>
              </div>
            )}
            {bubbles.map((b, i) => (
              <div key={i} className={`bubble ${b.role}`}>
                {b.tools.length > 0 && (
                  <div className="chat-tools">
                    {b.tools.map((t, j) => (
                      <span key={j} className={`chip${t.ok === false ? " bad" : ""}`}>
                        {t.ok === undefined ? "…" : t.ok ? "✓" : "✗"} {Object.hasOwn(TOOL_LABELS, t.name) ? TOOL_LABELS[t.name] : t.name}
                      </span>
                    ))}
                  </div>
                )}
                <div className="bubble-text">
                  {b.text ? <Linked text={b.text} /> : (busy && i === bubbles.length - 1 ? <span className="muted">Thinking…</span> : null)}
                </div>
                {b.actions.map((a) => (
                  <div key={a.id} className="proposal">
                    Proposed blocking <span className="mono">{a.ip}</span> (action #{a.id}). Nothing happens until
                    an analyst confirms it. <Link to="/actions">Review on the Actions page →</Link>
                  </div>
                ))}
                {b.error && <div className="error">{b.error}</div>}
              </div>
            ))}
            <div ref={bottom} />
          </div>
          <ErrorText error={error} />
          <form className="chat-input" onSubmit={submit}>
            <textarea value={input} maxLength={4000} rows={2} placeholder="Ask the assistant…"
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); void send(input); } }} />
            {busy
              ? <button type="button" onClick={() => abort.current?.abort()}>Stop</button>
              : <button className="primary" disabled={!input.trim()}>Send</button>}
          </form>
          <p className="muted" style={{ fontSize: 12, margin: "6px 0 0" }}>
            {status?.model ? `Model: ${status.model}. ` : ""}Answers can be wrong; check the data before acting.
          </p>
        </div>
        <div className="card">
          <div className="toolbar" style={{ justifyContent: "space-between" }}>
            <h2 style={{ margin: 0 }}>Conversations</h2>
            <button onClick={newChat} disabled={busy}>New</button>
          </div>
          {(history ?? []).map((c) => (
            <button key={c.id} className={`conv${c.id === conversationId ? " active" : ""}`} onClick={() => void open(c.id)} disabled={busy}>
              <span className="conv-title">{c.title || `Conversation #${c.id}`}</span>
              <span className="muted" style={{ fontSize: 11 }}>{dateTime(c.updated_at)}</span>
            </button>
          ))}
          {history?.length === 0 && <p className="muted">No conversations yet.</p>}
        </div>
      </div>
    </>
  );
}
