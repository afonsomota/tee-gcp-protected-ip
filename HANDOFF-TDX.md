# Handoff — TDX workaround for the AMD SEV-SNP attestation outage

**Date:** 2026-06-23 · **Project:** `tees-499001` · **VM:** `tee-example-cvm` (europe-west4-a)
**Status:** ✅ **DEPLOYED 2026-06-23** — CVM live on Intel TDX with real Confidential Space attestation (`hwmodel:GCP_INTEL_TDX`, endpoint serving on `35.204.201.134:8080`). Use the **production `confidential-space` image** (not `-debug`): debug images omit `STABLE` from `support_attributes`, which the KMS workload-identity gate requires, so debug breaks weights/harness delivery (see "KMS" below). Root cause confirmed Google-side & SEV-SNP-specific. AMD SEV-SNP remains the committed Terraform default; **revert when Google restores SEV-SNP**.

## TL;DR

Google Cloud Attestation is currently rejecting **AMD SEV-SNP** Confidential Space attestation with `UNSUPPORTED_CC_TECHNOLOGY`. **Intel TDX attests fine** on the identical image / service account / region / project. To get a real-attestation demo today, deploy the CVM on TDX. AMD SEV-SNP remains the committed default; TDX is a pure override.

## Symptom

`tee-example-cvm` shows `RUNNING` but the endpoint (`35.204.201.134:8080`) is dead. Serial console (the Confidential Space launcher) reaches attestation and then:

```
level=INFO  msg="attestation through TPM quote"
level=ERROR msg="failed to fetch and write OIDC token: ... calling v1.VerifyConfidentialSpace
  in europe-west4: Error 400: attestation failed: AMD SEV-SNP is not currently supported by
  Google Cloud Attestation ... reason = UNSUPPORTED_CC_TECHNOLOGY"
level=INFO  msg="TEE container launcher exiting" exit_code=4 exit_msg="VM remains running"
```

The container exits before our launcher binary runs, so the VM stays powered on but nothing serves on 8080. (The scale-from-zero controller cannot help — the workload dies at Google's attestation step, not at wake.)

## Root cause — evidence

Throwaway Confidential Space VMs, identical launcher image `…/launcher@sha256:0460a162…` and SA `tee-example-workload@…`:

| Region | CS guest image | CC tech | Result |
|---|---|---|---|
| europe-west4 | debug-260500 | SEV-SNP | ❌ `UNSUPPORTED_CC` |
| europe-west4 | debug-260400 | SEV-SNP | ❌ `UNSUPPORTED_CC` |
| europe-west4 | debug-260300 | SEV-SNP | ❌ `UNSUPPORTED_CC` |
| us-central1 | debug-260500 | SEV-SNP | ❌ `UNSUPPORTED_CC` |
| europe-west3 | debug-260500 | SEV-SNP | ❌ `UNSUPPORTED_CC` |
| **europe-west4** | **debug-260500** | **TDX (c3-standard-4)** | ✅ **PASS** — real token, `hwmodel:GCP_INTEL_TDX`, `launcher listening on 0.0.0.0:8080` |
| **europe-west4** | **confidential-space (prod, 260500)** | **TDX (c3-standard-4)** | ✅ **PASS** — `hwmodel:GCP_INTEL_TDX`, `dbgstat:disabled-since-boot`, `support_attributes:[LATEST STABLE USABLE]`, launcher listening — the KMS-compatible config |

→ **Not** image-version, **not** region, **not** our code. AMD SEV-SNP specifically is rejected; Intel TDX is accepted by the *same* `confidentialcomputing.googleapis.com` service in the same region/project. Conclusively Google-side and SEV-SNP-specific. (Cross-checks this session: each of the last 5 PRs + a clean production CS image, all under SEV-SNP — used to confirm no PR/config introduced it.)

**Context:** No incident on status.cloud.google.com for confidential computing. Likely tied to **GCP-2026-021** (a SEV-SNP firmware update → v4 attestation reports). Last known-good deploy was before ~2026-06-16.

## Workaround — deploy on Intel TDX

Terraform is parameterized so **AMD stays the default** and TDX is an override.

### Code changes (applied to the working tree this session)

- `infra/variables.tf` — new var `confidential_instance_type` (default `"SEV_SNP"`, validated to `SEV_SNP`|`TDX`).
- `infra/main.tf`:
  - `min_cpu_platform = var.confidential_instance_type == "SEV_SNP" ? "AMD Milan" : null`
  - `confidential_instance_type = var.confidential_instance_type`

### Apply — exact command used (2026-06-23)

State is in GCS (`bucket=tees-499001-tfstate`, `prefix=cvm`, workspace `default`) and reachable from a checked-out tree — **no tfvars file needed**: only `project_id` is a required variable; everything else defaults. You must still pass `image_digest` (its default is null → the destroy-only placeholder). **Leave `confidential_space_image_family` at its `confidential-space` (production) default — do not pass `-debug`** (the debug family fails the KMS gate; see "KMS" below).

```sh
terraform -chdir=infra apply \
  -replace=google_compute_instance.cvm \
  -target=google_compute_instance.cvm \
  -var project_id=tees-499001 \
  -var image_digest=sha256:0460a162739e5a265e538982ff32c8a6a9850ee3111b9d7ed5bdd29eaaadc0d2 \
  -var confidential_instance_type=TDX \
  -var machine_type=c3-standard-4 \
  -var idle_timeout_minutes=120
```

Notes / gotchas learned:
- **`-replace` is required**, not just a var change: `confidential_instance_type` (SEV_SNP→TDX) and the machine family change cannot apply in place — the instance must be destroyed + recreated.
- **`-target=google_compute_instance.cvm` still pulls the controller into the apply** (the CVM metadata depends on `google_cloudfunctions2_function.controller[0].url`). If the working tree is *ahead* of the deployed controller (e.g. includes PR #58), the controller gets redeployed too. This was harmless here — `frontend_origins` defaults to `https://journal.inner-apple.com`, so CORS stayed correct. If your tree's controller code is untrusted/unfinished, deploy from the matching commit or pass `-var frontend_origins='["https://journal.inner-apple.com"]'`.
- Static IP `35.204.201.134` (europe-west4) is reused via `nat_ip` on prod → **endpoint unchanged, no frontend rebuild**.
- `c3-standard-4` = 16 GiB RAM (same as `n2d-standard-4`); `on_host_maintenance = TERMINATE` already set (required for both).
- Don't pipe `terraform apply` through `head`/`grep | head` — an early pipe close can SIGPIPE the apply mid-run. Use `| tee` or no truncation.

### Verify

- Serial: `successfully refreshed attestation token … hwmodel:GCP_INTEL_TDX` then `launcher listening on 0.0.0.0:8080`.
- `curl http://35.204.201.134:8080/echo` (firewall opens tcp:8080).
- `scripts/verify-attestation.py` against the endpoint.

## KMS — why the production image, and why TDX still passes the gate

Weights/harness delivery (issues #7/#8) releases the KMS decrypt grant only to an attested enclave, via the workload-identity provider in `infra/bootstrap/main.tf`:

```hcl
attribute_condition = "assertion.swname == 'CONFIDENTIAL_SPACE'
                       && 'STABLE' in assertion.submods.confidential_space.support_attributes"
```

- **Debug images fail this** — their token carries `support_attributes:[LATEST USABLE]` (no `STABLE`) and `dbgstat:enabled`, so the assertion is rejected and KMS never releases the key. This is why a debug-image deploy serves `/echo`/`/attestation`/`/hpke-key` fine but would break `/chat` once weights are wired. **Don't deploy debug for anything past the no-weights demo.**
- **The condition is NOT hardware-gated** — no `hwmodel`/SEV-SNP check. The principalSet binds on `attribute.image_digest` (the launcher digest), which a TDX token carries identically. The production-image TDX test above shows `support_attributes:[LATEST STABLE USABLE]` + `dbgstat:disabled-since-boot` + the correct `image_digest`, so **production image + TDX satisfies the gate** — the TDX workaround survives the weights path unchanged.

## Frontend impact — none functional

- `frontend/src/attest/verify.ts` does **not** gate on hardware type — it checks `eat_nonce` (HPKE/TLS key binding), issuer, audience, and the expected image digest. A TDX token carries the same image digest + nonce binding and verifies unchanged.
- Only `frontend/src/components/KnowMorePage.tsx` says *"The enclave (AMD SEV-SNP)"* — cosmetic copy. Update to "Intel TDX" if you want accuracy during the TDX demo.

## Revert (once Google restores SEV-SNP)

```sh
terraform -chdir=infra apply -var project_id=tees-499001 -var image_digest=sha256:0460a162…
# defaults restore SEV_SNP + n2d-standard-4 + AMD Milan
```

Re-test SEV-SNP first with a throwaway VM (commands in the session transcript) before reverting the live instance.

## Open items

- File a Google Cloud support case: SEV-SNP attestation returns `UNSUPPORTED_CC_TECHNOLOGY` across europe-west4/us-central1/europe-west3 while TDX works; cite GCP-2026-021.
- Optional: a watcher that periodically tests SEV-SNP attestation and pings when it recovers, to revert automatically.
- Committed default stays AMD SEV-SNP per the product design (`docs/DESIGN.md`); TDX is a temporary demo lever only.
