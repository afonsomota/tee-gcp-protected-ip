---
id: 013
title: "Frontend CI to GitHub Pages with custom domain"
type: AFK
labels: [ready]
status: open
---

## What to build

A GitHub Actions workflow that builds the SPA (pnpm) on push to main and
deploys it to GitHub Pages on the project's domain (e.g. `journal.<domain>`,
with the enclave at `api.<domain>`). The expected enclave image digest and
API endpoint are build-time configuration.

Document the trust-on-first-use caveat where it's visible: the hosted
frontend is a convenience; the verification logic it runs could lie, so
paranoid users clone the repo and `pnpm dev` locally against the same
enclave. Local-run instructions live in the frontend README.

## Acceptance criteria

- [ ] Push to main deploys the SPA to GitHub Pages on the custom domain over HTTPS
- [ ] The deployed app talks to the live enclave (badge verifies, chat works)
- [ ] API endpoint and expected digest are explicit, documented config values
- [ ] Local-run path documented and works against the same enclave
- [ ] TOFU caveat stated in the README and on the "know more" page

## Blocked by

- 005-local-first-journal-frontend
