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
