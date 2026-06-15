import { useCallback, useEffect, useRef, useState } from "react";
import type { ChatMessage } from "../attest/chat";
import { hpkeChat } from "../attest/chat";
import type { AttestationStatus } from "../attest/session";
import { NETWORK_ERROR_CODE, runAttestation } from "../attest/session";
import { AttestationError } from "../attest/verify";
import { config } from "../lib/config";
import { AttestationBadge } from "./AttestationBadge";

export function ChatPane() {
  const [attestStatus, setAttestStatus] = useState<AttestationStatus>({ kind: "idle" });
  const [history, setHistory] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [sending, setSending] = useState(false);
  const [chatError, setChatError] = useState<string | null>(null);
  const bottomRef = useRef<HTMLDivElement>(null);

  const verify = useCallback(async () => {
    setAttestStatus({ kind: "verifying" });
    try {
      const result = await runAttestation(config.apiEndpoint, config.expectedImageDigest);
      setAttestStatus({ kind: "verified", ...result });
    } catch (err) {
      const code = err instanceof AttestationError ? err.code : NETWORK_ERROR_CODE;
      const detail = err instanceof Error ? err.message : String(err);
      setAttestStatus({ kind: "failed", code, detail });
    }
  }, []);

  useEffect(() => {
    void verify();
  }, [verify]);

  useEffect(() => {
    const onVisible = () => {
      if (document.visibilityState === "visible") void verify();
    };
    document.addEventListener("visibilitychange", onVisible);
    return () => document.removeEventListener("visibilitychange", onVisible);
  }, [verify]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [history]);

  const canChat = attestStatus.kind === "verified";

  async function handleSend() {
    // Narrowing the discriminated union gates chat AND types hpkePublicKey.
    if (attestStatus.kind !== "verified" || input.trim() === "" || sending) return;
    const hpkeKey = attestStatus.hpkePublicKey;

    const userMessage: ChatMessage = { role: "user", content: input.trim() };
    const nextHistory = [...history, userMessage];
    setHistory(nextHistory);
    setInput("");
    setSending(true);
    setChatError(null);

    try {
      const reply = await hpkeChat(config.apiEndpoint, hpkeKey, nextHistory);
      setHistory([...nextHistory, { role: "assistant", content: reply }]);
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
        {history.length === 0 && (
          <p className="chat-empty muted">
            {canChat
              ? "Your messages are end-to-end encrypted and processed only inside the verified enclave."
              : "Chat is disabled until the enclave is verified."}
          </p>
        )}
        {history.map((msg, i) => (
          <div key={i} className={`chat-bubble chat-bubble--${msg.role}`}>
            {msg.content}
          </div>
        ))}
        {sending && (
          <div className="chat-bubble chat-bubble--assistant chat-bubble--thinking muted">
            …
          </div>
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
