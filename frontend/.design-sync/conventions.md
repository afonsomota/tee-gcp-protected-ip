# TEE Journal UI — how to build with these components

`window.TeeJournalUI` exposes five React components from the **tee-journal** app:
a local-first, end-to-end-encrypted journal with a confidential-enclave chatbot.
These are **app-level screens and panes**, not atomic primitives — compose them
as whole views, not as building blocks for unrelated UIs.

## No provider, no wrapper

There is no `ThemeProvider`, context, or root wrapper. Import a component (use
`window.TeeJournalUI.<Name>`, bundle at the root `_ds_bundle.js`) and render it
with props — all styling comes from the global stylesheet, never from a runtime
provider:

```jsx
const { AttestationBadge } = window.TeeJournalUI;
<AttestationBadge status={{ kind: "verified", signatureVerified: true }} onRetry={() => {}} />
```

## Styling idiom: global CSS classes + CSS custom properties

This is **not** a utility-class system (no `bg-*`/`gap-*`) and **not** prop-based
theming. Every component ships pre-styled via semantic class names in the bound
`styles.css` (which `@import`s `_ds_bundle.css`). You do **not** pass `className`
to style these components — they own their classes (`.attest-badge`, `.chat-pane`,
`.journal`, `.passphrase-card`, `.know-more`, …).

When you write your **own** layout/glue around them, match the system's vocabulary
instead of inventing one:

- **Tokens** (defined on `:root`): `var(--accent)` — the brand/primary colour
  (#4f6df5); `var(--border)` — subtle hairline borders; `var(--muted)` —
  secondary text. `color-scheme: light dark` is set, so colours adapt to the
  theme; use `currentColor`/`color-mix` like the stylesheet does rather than
  hard-coding greys.
- **Buttons** are styled by element + modifier class: a bare `<button>` is the
  filled accent button; `<button className="secondary">` is the ghost/outline
  variant; `<button className="danger">` is destructive (red).
- **Inputs and textareas** are styled by element (transparent background,
  `var(--border)` outline, 6px radius) — no class needed.
- **`.muted`** on any element renders secondary/dimmed text.

The bound `styles.css` (and the `_ds_bundle.css` it imports) is the source of
truth for the full class and token vocabulary — read it before adding styles.
Each component's `.prompt.md` and `.d.ts` document its exact props.

## The five components

- **PassphraseScreen** — the local-first unlock/create login card (passphrase →
  client-side AES key, no accounts). Centred `.passphrase-card`.
- **JournalView** — the full three-pane app: entry sidebar, editor, and chat
  pane. Full-height (`height: 100vh`); give it the whole viewport.
- **ChatPane** — the enclave chat column (transcript, input, attestation badge).
  Driven by a `session` prop carrying the attestation status.
- **AttestationBadge** — the small pill showing enclave verification state
  (`status.kind`: idle / verifying / warming / verified / failed). The trust
  indicator; place it wherever the user needs to see the enclave is verified.
- **KnowMorePage** — the static "how your privacy is protected" explainer page.

## One idiomatic composition

```jsx
const { AttestationBadge } = window.TeeJournalUI;

function StatusBar() {
  return (
    <header
      style={{
        display: "flex",
        gap: "1rem",
        alignItems: "center",
        padding: "0.8rem 1rem",
        borderBottom: "1px solid var(--border)",
      }}
    >
      <strong>Private Journal</strong>
      <AttestationBadge
        status={{ kind: "verified", signatureVerified: true }}
        onRetry={() => {}}
      />
      <button className="secondary" style={{ marginLeft: "auto" }}>
        Lock
      </button>
    </header>
  );
}
```

The real component drives the control; the system's `var(--border)` token and the
`button.secondary` variant style the surrounding glue.
