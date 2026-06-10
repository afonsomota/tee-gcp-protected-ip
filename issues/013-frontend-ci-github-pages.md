---
id: 013
title: "Frontend CI to GitHub Pages with custom domain"
type: AFK
labels: [ready]
status: needs-review
---

> **Status note (2026-06-10):** Implemented: `.github/workflows/deploy-frontend.yml`
> (pnpm install/test/build → Pages via configure-pages/upload-pages-artifact/
> deploy-pages, CNAME from `vars.FRONTEND_DOMAIN`), typed build-time config in
> `frontend/src/lib/config.ts` (`VITE_API_ENDPOINT`, `VITE_EXPECTED_IMAGE_DIGEST`,
> one vitest test), and `frontend/README.md` (local-run, config values, TOFU
> caveat, one-time Pages/DNS/variables setup). Validated locally: YAML parses,
> tests pass, env-injected `pnpm build` passes.
>
> **Live-deploy update (2026-06-10):** GitHub repo now exists
> (`afonsomota/tee-gcp-protected-ip`). Pages enabled with the Actions build
> source (HTTPS enforced); workflow run 27308067395 passed end-to-end
> (install → test → build → deploy) and the SPA is live at
> <https://afonsomota.github.io/tee-gcp-protected-ip/> (HTTP/2 200, assets
> path-relative). Still deferred: custom domain (needs `FRONTEND_DOMAIN` repo
> variable + a DNS CNAME — no domain chosen yet), and `VITE_API_ENDPOINT` /
> `VITE_EXPECTED_IMAGE_DIGEST` repo variables plus the deployed-app-talks-to-
> live-enclave check (enclave currently destroyed; badge/"know more" page
> arrive with issue 009).

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
