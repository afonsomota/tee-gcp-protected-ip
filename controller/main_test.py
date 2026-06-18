"""Unit tests for the scale-from-zero controller logic (issue #45).

The GCP clients are injected fakes, so these run with no cloud access and no
google-cloud libraries imported (the real-client wrappers are only constructed
inside the HTTP entry point, which these tests don't exercise)."""

import datetime

import main


class FakeInstances:
    def __init__(self, status):
        self._status = status
        self.started = 0
        self.stopped = 0

    def status(self, project, zone, instance):
        return self._status

    def start(self, project, zone, instance):
        self.started += 1
        self._status = main.RUNNING

    def stop(self, project, zone, instance):
        self.stopped += 1
        self._status = main.TERMINATED


class FakeLedger:
    def __init__(self, count):
        self._count = count
        self.since = None

    def count_since(self, project, since):
        self.since = since
        return self._count


# --- wake -------------------------------------------------------------------


def test_wake_starts_a_terminated_vm():
    vm = FakeInstances(main.TERMINATED)
    body, status = main.handle_wake(vm, "p", "z", "cvm")
    assert status == 202
    assert body["status"] == "warming"
    assert vm.started == 1


def test_wake_is_a_noop_when_already_running():
    vm = FakeInstances(main.RUNNING)
    body, status = main.handle_wake(vm, "p", "z", "cvm")
    assert status == 200
    assert body["status"] == "running"
    assert vm.started == 0


def test_wake_does_not_double_start_a_transitioning_vm():
    vm = FakeInstances("STOPPING")
    body, status = main.handle_wake(vm, "p", "z", "cvm")
    assert status == 202
    assert body["status"] == "warming"
    # No redundant start while a transition is already under way.
    assert vm.started == 0


# --- idle / budget ----------------------------------------------------------


def test_idle_stops_when_under_budget():
    vm = FakeInstances(main.RUNNING)
    ledger = FakeLedger(count=2)
    body, status = main.handle_idle(vm, ledger, "p", "z", "cvm", max_weekly_boots=4)
    assert status == 202
    assert body["action"] == "stopped"
    assert body["issued_last_7d"] == 2
    assert vm.stopped == 1


def test_idle_keeps_vm_warm_at_budget():
    vm = FakeInstances(main.RUNNING)
    ledger = FakeLedger(count=4)
    body, status = main.handle_idle(vm, ledger, "p", "z", "cvm", max_weekly_boots=4)
    assert status == 200
    assert body["action"] == "kept_warm"
    assert body["issued_last_7d"] == 4
    # The whole point: never stop when a restart would breach the cert budget.
    assert vm.stopped == 0


def test_idle_counts_over_a_trailing_seven_day_window():
    vm = FakeInstances(main.RUNNING)
    ledger = FakeLedger(count=0)
    before = main._utcnow() - datetime.timedelta(days=7)
    main.handle_idle(vm, ledger, "p", "z", "cvm", max_weekly_boots=4)
    after = main._utcnow() - datetime.timedelta(days=7)
    assert ledger.since is not None
    # The window start is "now minus 7 days", computed at call time.
    assert before <= ledger.since <= after


# --- CORS -------------------------------------------------------------------


def test_cors_falls_back_to_wildcard_when_no_allowlist(monkeypatch):
    monkeypatch.delenv("ALLOWED_ORIGINS", raising=False)
    headers = main.cors_headers("https://journal.inner-apple.com")
    # Unconfigured deployments / local dev keep working with a permissive ACAO.
    assert headers["Access-Control-Allow-Origin"] == "*"
    assert "POST" in headers["Access-Control-Allow-Methods"]
    assert "OPTIONS" in headers["Access-Control-Allow-Methods"]
    # No Vary needed when we don't echo a specific origin.
    assert "Vary" not in headers


def test_cors_echoes_an_allowlisted_origin(monkeypatch):
    monkeypatch.setenv(
        "ALLOWED_ORIGINS",
        "https://journal.inner-apple.com, https://afonsomota.github.io",
    )
    headers = main.cors_headers("https://afonsomota.github.io")
    assert headers["Access-Control-Allow-Origin"] == "https://afonsomota.github.io"
    assert headers["Vary"] == "Origin"


def test_cors_rejects_an_unlisted_origin(monkeypatch):
    monkeypatch.setenv("ALLOWED_ORIGINS", "https://journal.inner-apple.com")
    headers = main.cors_headers("https://evil.example.com")
    # A mismatch echoes an allowlisted origin (not the caller's), so the browser
    # cleanly blocks the response instead of getting an open `*`.
    assert headers["Access-Control-Allow-Origin"] == "https://journal.inner-apple.com"


class FakeRequest:
    def __init__(self, method="POST", path="/wake", origin=None):
        self.method = method
        self.path = path
        self.headers = {"Origin": origin} if origin else {}


def test_options_preflight_returns_cors_without_touching_the_vm(monkeypatch):
    # A preflight must never start or stop the instance: force any VM-client
    # construction to blow up so the test fails if the OPTIONS branch falls
    # through to the wake/idle dispatch.
    def _boom():
        raise AssertionError("OPTIONS preflight must not construct a VM client")

    monkeypatch.setattr(main, "ComputeInstances", _boom)
    monkeypatch.setenv("ALLOWED_ORIGINS", "https://journal.inner-apple.com")
    body, status, headers = main.controller(
        FakeRequest(method="OPTIONS", origin="https://journal.inner-apple.com")
    )
    assert status == 204
    assert headers["Access-Control-Allow-Origin"] == "https://journal.inner-apple.com"
    assert "OPTIONS" in headers["Access-Control-Allow-Methods"]
