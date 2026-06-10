# TEE Journal — Frontend

React + Vite + TypeScript SPA (pnpm). Entries are encrypted client-side and
stored local-first in IndexedDB; chat goes to the enclave over HPKE. The app
verifies the enclave's attestation in the browser and shows a badge
(issue 009).

## Trust-on-first-use caveat

**The hosted frontend is a convenience, not the root of trust.** When you
load it from our domain, you are trusting whoever serves the JavaScript on
first use: a malicious or compromised deployment could ship verification
logic that *lies* — show a green badge without checking the attestation, or
exfiltrate your passphrase. The enclave attestation protects you from the
*server* operator, but not from the *frontend* operator (here, the same
party).

If you are paranoid (good!), don't run our hosted copy — run the frontend
yourself from source against the same enclave:

```sh
git clone <this-repo>
cd frontend
pnpm install
VITE_API_ENDPOINT=https://api.example.com \
VITE_EXPECTED_IMAGE_DIGEST=sha256:<expected-enclave-digest> \
pnpm dev
```

Read the verification code, then let *your* build of it check the enclave.
The in-app "know more" page (arriving with the attestation badge, issue 009)
states this same caveat next to the badge.

## Configuration

All configuration is explicit and baked in at build time via Vite env vars,
read by [`src/lib/config.ts`](src/lib/config.ts):

| Variable | Meaning | Default if unset |
| --- | --- | --- |
| `VITE_API_ENDPOINT` | Base URL of the enclave API | `http://localhost:8080` (local launcher) |
| `VITE_EXPECTED_IMAGE_DIGEST` | Enclave container image digest (`sha256:...`) the attestation badge must match | `""` — no pinned digest; the badge cannot verify |

For local development you can put these in `.env.local` (see
[`.env.example`](.env.example)) instead of prefixing every command.

The values used for the hosted deployment come from GitHub repo variables of
the same names (see below), so anyone can audit what the published app was
built against.

## Local development

```sh
pnpm install
pnpm dev        # dev server; talks to http://localhost:8080 by default
pnpm test       # vitest
pnpm build      # type-check + production build into dist/
```

To point a local dev instance at the live enclave, set the env vars shown in
the TOFU section above (same enclave, your own verification code).

## Deployment (GitHub Pages)

Pushes to `main` that touch `frontend/**` trigger
[`.github/workflows/deploy-frontend.yml`](../.github/workflows/deploy-frontend.yml):
pnpm install → test → build → deploy `frontend/dist` to GitHub Pages, with a
`CNAME` file for the custom domain. The SPA lives at `journal.<domain>` and
the enclave at `api.<domain>`.

### One-time repo setup

1. **Enable Pages with the GitHub Actions source**: repo Settings → Pages →
   "Build and deployment" → Source: **GitHub Actions**.
2. **Set repo variables** (Settings → Secrets and variables → Actions →
   Variables):
   - `FRONTEND_DOMAIN` — the custom domain, e.g. `journal.example.com`.
     If unset, the workflow skips the `CNAME` file and the site is served
     from the default `https://<owner>.github.io/<repo>/` URL.
   - `VITE_API_ENDPOINT` — e.g. `https://api.example.com`.
   - `VITE_EXPECTED_IMAGE_DIGEST` — the pinned enclave image digest from the
     release flow (`make release` / `make deploy`).
3. **DNS**: add a `CNAME` record for `journal.<domain>` pointing at
   `<owner>.github.io`. After the first deploy, confirm the custom domain in
   Settings → Pages and enable **Enforce HTTPS** once the certificate is
   provisioned.
4. After updating the enclave (new image digest), update
   `VITE_EXPECTED_IMAGE_DIGEST` and re-run the workflow (or push) so the
   deployed badge expects the new digest.
