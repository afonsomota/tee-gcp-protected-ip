---
id: 014
title: "Docs suite and verify-it-yourself CLI"
type: AFK
labels: [ready]
status: open
---

## What to build

The documentation that makes this an *example* rather than just an app, plus
a verifier CLI that walks the full trust chain.

Docs (in `docs/`):
- `architecture.md` — components, flows, and the open/closed boundary
- `threat-model.md` — the two TCBs (user privacy vs company IP), what each
  party can and cannot do, and the explicit out-of-scope list from DESIGN.md
- `verifying.md` — step-by-step: verify the attestation token, check the
  image digest, validate kettle provenance back to the git commit, and the
  self-rebuild fallback

Verifier CLI: one command that performs the whole chain against a live
deployment — fetch token → verify Google signature → extract digest →
fetch provenance → verify hardware signature → print the git commit the
running code was built from. This is what the badge's "know more" page
links to as the skeptic's path.

## Acceptance criteria

- [ ] Verifier CLI runs the full chain against the live deployment and prints commit + pass/fail per step
- [ ] Each CLI step maps to a section in verifying.md explaining what was just proven and what is still assumed
- [ ] threat-model.md covers both TCBs, the untrusted-harness argument, TOFU, and out-of-scope items
- [ ] Root README tells the company/user story and links every doc
- [ ] A reader following only the docs can reproduce verification without reading source code

## Blocked by

- 012-kettle-release-pipeline
