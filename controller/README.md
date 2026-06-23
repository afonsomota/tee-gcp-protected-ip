# Controller — scale-from-zero front door (issue #45)

A tiny, always-reachable Cloud Function (gen2, Python) that toggles the
Confidential Space CVM between `TERMINATED` (no compute cost) and `RUNNING`.
Confidential Space has no serverless mode for SEV-SNP or TDX, so "scale from zero" is
**stop/start one CVM** fronted by this controller.

**It is outside the audited TCB and holds no privacy trust.** The frontend
re-attests on every (re)connect — a restarted enclave has fresh keys and a
fresh Google-signed token, verified from scratch — so whatever starts the VM
is granted nothing. See `docs/DESIGN.md`.

## Endpoints

| Path | Caller | Behaviour |
|---|---|---|
| `POST /wake` | browser, when the API is unreachable | `instances.start` if `TERMINATED` → 202 `warming`; 200 if already `RUNNING`; 202 (no-op) while transitioning |
| `POST /idle` | the launcher, after its idle timeout | count `tls certificate issued` log lines in the trailing 7 days; if `< MAX_WEEKLY_BOOTS` → `instances.stop` (202 `stopped`), else leave running (200 `kept_warm`) |

The budget gate is the crux: a stop forces a fresh Let's Encrypt cert on the
next boot, and prod allows only 5 certs / 7 days. Rather than fight that, the
controller **declines to stop** when issuance would breach the cap — the VM
stays warm (pays compute) instead of ever locking out TLS. The rate limit
becomes a cost knob, never a wall.

The issuance count comes from Cloud Logging: the launcher logs the marker once
per boot (`launcher/src/acme_cache.rs`), redirected to Cloud Logging by the
CVM's `tee-container-log-redirect`. crt.sh/CT is the documented fallback, not
built.

## Configuration (environment variables, set by Terraform)

| Var | Meaning |
|---|---|
| `CVM_PROJECT` | project id (falls back to the runtime's `GOOGLE_CLOUD_PROJECT`) |
| `INSTANCE_NAME` | the CVM's instance name |
| `INSTANCE_ZONE` | the CVM's zone |
| `MAX_WEEKLY_BOOTS` | cold-boot cap per rolling 7 days (default 4; keep `< 5`) |
| `ALLOWED_ORIGINS` | comma-separated CORS allowlist of browser origins; empty ⇒ falls back to `*` |

The SPA calls `/wake` cross-origin (it is served from GitHub Pages, not the
Cloud Functions domain), so every response — including the `OPTIONS` preflight —
carries `Access-Control-Allow-Origin`. `ALLOWED_ORIGINS` is the `frontend_origins`
Terraform variable. CORS is not an auth boundary here (the controller is
unauthenticated; trust is re-established by attestation), it only lets the
browser read a response it already reached.

`MAX_WEEKLY_BOOTS` is the `max_weekly_boots` Terraform variable; the launcher's
idle timeout is the separate `idle_timeout_minutes` variable (delivered to the
CVM as instance metadata). See `infra/` and the issue for the two knobs.

## IAM

The controller's service account holds a least-privilege custom role —
`compute.instances.get` / `.start` / `.stop` (+ `compute.zoneOperations.get`) —
plus `roles/logging.viewer` for the cert count. It does **not** get broad
`instanceAdmin`. `allUsers` may invoke the function (the browser's `/wake` is
unauthenticated); the worst an anonymous caller can do is start a stopped VM or
ask to stop an idle one (budget-gated) — both already part of normal operation.

## Tests

```sh
uv run --with functions-framework --with pytest pytest controller/
```

The tests inject fake GCP clients (no cloud access); the real
`google-cloud-compute` / `google-cloud-logging` wrappers are constructed only
inside the HTTP entry point, which the unit tests don't exercise.

## Deploy

Terraform (`infra/`) packages this directory and deploys it as part of the CVM
root when `scale_to_zero` is enabled (the default for prod). No manual step.
