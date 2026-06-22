"""Scale-from-zero controller for the Confidential Space CVM (issue #45).

This is the *untrusted*, always-on front door that toggles one CVM between
``TERMINATED`` (no compute cost) and ``RUNNING``. It is deliberately outside
the audited TCB: it holds no user data and is granted no privacy trust. The
frontend re-attests on every (re)connect, so a restarted enclave with fresh
keys is verified from scratch — whatever started the VM earns nothing.

Two endpoints, dispatched by path (Cloud Functions gen2 routes every path to
this single entry point):

* ``POST /wake``  — the browser hits this when the API is unreachable. If the
  CVM is ``TERMINATED`` we ``instances.start`` and return 202 "warming"; if it
  is already running we return 200; transitional states return 202 without
  acting.
* ``POST /idle``  — the launcher pokes this after its idle timeout. We count
  "tls certificate issued" log lines over the trailing 7 days and, only if
  that is below ``MAX_WEEKLY_BOOTS``, ``instances.stop`` the VM. Otherwise we
  leave it running: stopping would force a fresh cert on the next boot and
  could breach Let's Encrypt's 5-certs-per-7-days production limit, so the
  rate limit becomes a cost knob (pay to stay warm) instead of a TLS lockout.

Config is environment variables (set by Terraform):

==================  =========================================================
``CVM_PROJECT``     project id (falls back to runtime ``GOOGLE_CLOUD_PROJECT``)
``INSTANCE_NAME``   the CVM's instance name
``INSTANCE_ZONE``   the CVM's zone
``MAX_WEEKLY_BOOTS``cold-boot cap per rolling 7 days (default 4; keep < 5)
``ALLOWED_ORIGINS`` comma-separated CORS allowlist; empty ⇒ ``*`` (issue #57)
==================  =========================================================

Every response — wake, idle, the 404, and the CORS preflight ``OPTIONS`` — must
carry ``Access-Control-Allow-Origin`` because the SPA calls this cross-origin
from GitHub Pages; without it the browser blocks the response. CORS is not an
auth boundary (the controller is unauthenticated and trust comes from
re-attestation), it only lets the browser read what it already reached.
"""

from __future__ import annotations

import datetime
import os
from typing import Protocol

import functions_framework

# The launcher emits exactly this prefix once per boot, right after the cert is
# deployed (launcher/src/acme_cache.rs). The log text is the issuance ledger.
CERT_ISSUED_MARKER = "tls certificate issued"
DEFAULT_MAX_WEEKLY_BOOTS = 4
# Compute statuses that mean "a start would be wasted / premature".
RUNNING = "RUNNING"
TERMINATED = "TERMINATED"


def _project() -> str:
    # Terraform passes CVM_PROJECT explicitly; GOOGLE_CLOUD_PROJECT is the
    # runtime-provided fallback. (GCP_* / GOOGLE_* names that Terraform sets are
    # rejected as reserved, hence the CVM_ prefix.)
    project = os.environ.get("CVM_PROJECT") or os.environ.get("GOOGLE_CLOUD_PROJECT")
    if not project:
        raise RuntimeError("CVM_PROJECT is not set")
    return project


def _max_weekly_boots() -> int:
    return int(os.environ.get("MAX_WEEKLY_BOOTS", DEFAULT_MAX_WEEKLY_BOOTS))


def _allowed_origins() -> list[str]:
    """Comma-separated allowlist of browser origins permitted to read responses.
    Unset/empty means "no allowlist" — we fall back to ``*`` so local/dev and
    unconfigured deployments keep working."""
    raw = os.environ.get("ALLOWED_ORIGINS", "")
    return [o.strip() for o in raw.split(",") if o.strip()]


def cors_headers(origin: str | None) -> dict[str, str]:
    """CORS response headers for a cross-origin browser caller. The controller
    is unauthenticated either way — CORS is not a security control here (the
    privacy guarantee comes from re-attestation, not from this front door); it
    only lets the browser *read* the response. We echo a permitted ``Origin``
    and otherwise fall back to ``*`` when no allowlist is configured."""
    allowlist = _allowed_origins()
    if not allowlist:
        allow = "*"
    elif origin and origin in allowlist:
        allow = origin
    else:
        # Origin not permitted: send the first allowlisted origin so the browser
        # blocks it (a mismatch is a clean CORS failure, not an open door).
        allow = allowlist[0]
    headers = {
        "Access-Control-Allow-Origin": allow,
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
    }
    if allow != "*":
        # Tell caches the response varies by Origin once we echo a specific one.
        headers["Vary"] = "Origin"
    return headers


# --- GCP client seams -------------------------------------------------------
# The handlers take these as parameters so tests can inject fakes; main()
# builds the real google-cloud clients and passes them in.


class InstanceClient(Protocol):
    def status(self, project: str, zone: str, instance: str) -> str: ...

    def start(self, project: str, zone: str, instance: str) -> None: ...

    def stop(self, project: str, zone: str, instance: str) -> None: ...


class CertLedger(Protocol):
    def count_since(self, project: str, since: datetime.datetime) -> int: ...


def handle_wake(instances: InstanceClient, project: str, zone: str, instance: str):
    """Start the CVM if it is stopped. Idempotent: safe to call repeatedly
    while the browser polls — a start in flight just returns "warming"."""
    status = instances.status(project, zone, instance)
    if status == RUNNING:
        return {"status": "running"}, 200
    if status == TERMINATED:
        instances.start(project, zone, instance)
        return {"status": "warming", "from": status}, 202
    # PROVISIONING / STAGING / STOPPING / SUSPENDED: a transition is already
    # under way; don't issue a redundant start, just tell the browser to wait.
    return {"status": "warming", "from": status}, 202


def handle_idle(
    instances: InstanceClient,
    ledger: CertLedger,
    project: str,
    zone: str,
    instance: str,
    max_weekly_boots: int,
):
    """Stop the idle CVM, but only while doing so stays inside the weekly cert
    budget. At or above the cap we leave it running — paying compute beats
    locking out TLS."""
    since = _utcnow() - datetime.timedelta(days=7)
    issued = ledger.count_since(project, since)
    if issued >= max_weekly_boots:
        # A stop now would (on the next wake) order cert number issued+1; refuse
        # so the budget — and therefore TLS availability — is never breached.
        return {
            "action": "kept_warm",
            "reason": "weekly cert budget reached",
            "issued_last_7d": issued,
            "max_weekly_boots": max_weekly_boots,
        }, 200
    instances.stop(project, zone, instance)
    return {
        "action": "stopped",
        "issued_last_7d": issued,
        "max_weekly_boots": max_weekly_boots,
    }, 202


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


# --- Real GCP clients -------------------------------------------------------


class ComputeInstances:
    """Thin wrapper over google-cloud-compute. start/stop are fire-and-forget:
    we deliberately do NOT wait on the returned operation — the browser polls
    attestation for readiness, and a controller that blocks for minutes would
    just burn invocation time."""

    def __init__(self):
        from google.cloud import compute_v1

        self._client = compute_v1.InstancesClient()

    def status(self, project: str, zone: str, instance: str) -> str:
        vm = self._client.get(project=project, zone=zone, instance=instance)
        return vm.status

    def start(self, project: str, zone: str, instance: str) -> None:
        self._client.start(project=project, zone=zone, instance=instance)

    def stop(self, project: str, zone: str, instance: str) -> None:
        self._client.stop(project=project, zone=zone, instance=instance)


class LoggingLedger:
    """Counts CERT_ISSUED_MARKER entries via the Cloud Logging API. Only the
    launcher emits that string, so a plain text match scoped to gce_instance
    logs is enough; we stop early once the cap is reached (the exact count
    beyond the cap is irrelevant to the decision)."""

    def __init__(self, cap: int):
        from google.cloud import logging as cloud_logging

        self._client = cloud_logging.Client()
        # Count at most cap entries: handle_idle only compares against the cap.
        self._cap = cap

    def count_since(self, project: str, since: datetime.datetime) -> int:
        ts = since.strftime("%Y-%m-%dT%H:%M:%SZ")
        filter_ = (
            'resource.type="gce_instance" '
            f'AND timestamp>="{ts}" '
            f'AND "{CERT_ISSUED_MARKER}"'
        )
        count = 0
        for _ in self._client.list_entries(filter_=filter_):
            count += 1
            if count >= self._cap:
                break
        return count


# --- HTTP entry point -------------------------------------------------------


@functions_framework.http
def controller(request):
    # The browser calls this cross-origin (the SPA is served from GitHub Pages,
    # not the Cloud Functions domain), so every response — including the 404 and
    # the OPTIONS preflight — must carry CORS headers or the browser blocks it.
    cors = cors_headers(request.headers.get("Origin"))

    # CORS preflight: answer with the allow-headers and do NOT touch the VM.
    if request.method == "OPTIONS":
        return ("", 204, cors)

    project = _project()
    zone = os.environ["INSTANCE_ZONE"]
    instance = os.environ["INSTANCE_NAME"]
    max_boots = _max_weekly_boots()

    path = request.path.rstrip("/")
    if path.endswith("/wake"):
        instances = ComputeInstances()
        body, status = handle_wake(instances, project, zone, instance)
        return (body, status, cors)
    if path.endswith("/idle"):
        instances = ComputeInstances()
        ledger = LoggingLedger(max_boots)
        body, status = handle_idle(
            instances, ledger, project, zone, instance, max_boots
        )
        return (body, status, cors)
    return ({"error": "not found", "path": request.path}, 404, cors)
