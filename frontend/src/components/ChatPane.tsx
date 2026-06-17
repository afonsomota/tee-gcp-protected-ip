import { useEffect, useMemo, useRef, useState } from "react";
import type { ChatMessage, ToolActivity } from "../attest/chat";
import { hpkeChat } from "../attest/chat";
import { makeToolExecutor } from "../attest/tools";
import type { EnclaveSession } from "../attest/useEnclaveSession";
import { config } from "../lib/config";
import type { JournalDb } from "../lib/store";
import { AttestationBadge } from "./AttestationBadge";

interface Props {
  /** The unlocked journal — the client tools read and write entries through it. */
  db: JournalDb;
  journalKey: CryptoKey;
  /** The shared, verified enclave session (attestation + pinned HPKE key). */
  session: EnclaveSession;
}

/**
 * One item in the chat transcript: a user/assistant message, or a record of a
 * tool the enclave asked the browser to run. Tool items make the
 * data-minimization flow visible — the user sees exactly what left their device.
 */
type ChatItem =
  | { kind: "message"; role: "user" | "assistant"; content: string }
  | { kind: "tool"; activity: ToolActivity };

export function ChatPane({ db, journalKey, session }: Props) {
  const { status: attestStatus, verify } = session;
  const [items, setItems] = useState<ChatItem[]>([]);
  const [input, setInput] = useState("");
  const [sending, setSending] = useState(false);
  const [chatError, setChatError] = useState<string | null>(null);
  const bottomRef = useRef<HTMLDivElement>(null);

  // The tool executor is bound to the unlocked journal; rebuild it only if the
  // db or key changes (e.g. after a re-unlock).
  const executeTool = useMemo(() => makeToolExecutor(db, journalKey), [db, journalKey]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [items, sending]);

  const canChat = attestStatus.kind === "verified";

  // Append a new tool item, or update an existing one in place as its status
  // moves running → done/error.
  function recordActivity(activity: ToolActivity) {
    setItems((prev) => {
      const idx = prev.findIndex(
        (item) => item.kind === "tool" && item.activity.id === activity.id,
      );
      if (idx === -1) return [...prev, { kind: "tool", activity }];
      const next = prev.slice();
      next[idx] = { kind: "tool", activity };
      return next;
    });
  }

  async function handleSend() {
    // Narrowing the discriminated union gates chat AND types hpkePublicKey.
    if (attestStatus.kind !== "verified" || input.trim() === "" || sending) return;
    const hpkeKey = attestStatus.hpkePublicKey;

    const userMessage: ChatMessage = { role: "user", content: input.trim() };
    // The enclave only ever sees the user/assistant transcript; tool items are
    // local UI state, never sent.
    const priorHistory = items
      .filter((item): item is Extract<ChatItem, { kind: "message" }> => item.kind === "message")
      .map(({ role, content }) => ({ role, content }) satisfies ChatMessage);
    const nextHistory = [...priorHistory, userMessage];

    setItems((prev) => [...prev, { kind: "message", ...userMessage }]);
    setInput("");
    setSending(true);
    setChatError(null);

    try {
      const reply = await hpkeChat(config.apiEndpoint, hpkeKey, nextHistory, {
        executeTool,
        onActivity: recordActivity,
      });
      setItems((prev) => [...prev, { kind: "message", role: "assistant", content: reply }]);
    } catch (err) {
      // If chat fails with a key error, re-verify (enclave may have restarted)
      const msg = err instanceof Error ? err.message : String(err);
      setChatError(msg);
      // Trigger re-attestation so session keys are refreshed on next send
      void verify();
    } finally {
      setSending(false);
    }
  }

  return (
    <section className="chat-pane">
      <header className="chat-header">
        <h2>Private chat</h2>
        <AttestationBadge status={attestStatus} onRetry={() => void verify()} />
      </header>

      <div className="chat-messages">
        {items.length === 0 && (
          <p className="chat-empty muted">
            {canChat
              ? "Your messages are end-to-end encrypted and processed only inside the verified enclave."
              : "Chat is disabled until the enclave is verified."}
          </p>
        )}
        {items.map((item, i) =>
          item.kind === "message" ? (
            <div key={i} className={`chat-bubble chat-bubble--${item.role}`}>
              {item.content}
            </div>
          ) : (
            <div
              key={i}
              className={`chat-tool chat-tool--${item.activity.status}`}
              title={`Tool: ${item.activity.name}`}
            >
              <span className="chat-tool-icon" aria-hidden="true">
                {item.activity.name === "search_entries" ? "🔍" : "🏷️"}
              </span>
              <span className="chat-tool-summary">{item.activity.summary}</span>
            </div>
          ),
        )}
        {sending && (
          <div className="chat-bubble chat-bubble--assistant chat-bubble--thinking muted">…</div>
        )}
        {chatError !== null && <p className="chat-error">{chatError}</p>}
        <div ref={bottomRef} />
      </div>

      <form
        className="chat-input-row"
        onSubmit={(e) => {
          e.preventDefault();
          void handleSend();
        }}
      >
        <input
          className="chat-input"
          placeholder={canChat ? "Message the enclave…" : "Waiting for enclave verification…"}
          value={input}
          disabled={!canChat || sending}
          onChange={(e) => setInput(e.target.value)}
        />
        <button type="submit" disabled={!canChat || sending || input.trim() === ""}>
          Send
        </button>
      </form>
    </section>
  );
}
