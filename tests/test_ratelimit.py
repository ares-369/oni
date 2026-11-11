"""Tests for per-target pacing (scope.rate_limit_per_min) and 429/503 backoff.

Everything runs on a fake clock and fake sleep: nothing here really waits, and
nothing touches the network or SSH."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from email.utils import format_datetime

import pytest

from oniops import aisec
from oniops.kali import CmdResult, KaliRunner
from oniops.ratelimit import (
    RateLimiter,
    Throttled,
    backoff_delay,
    execute_with_backoff,
    parse_retry_after,
    response_throttle_status,
    target_key_from_command,
)


class FakeClock:
    def __init__(self):
        self.now = 1000.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, secs: float) -> None:
        self.sleeps.append(secs)
        self.now += secs


def _limiter(rate: int, clock: FakeClock) -> RateLimiter:
    return RateLimiter(rate, monotonic=clock.monotonic, sleep=clock.sleep)


# ───────────────────────── limiter ─────────────────────────
def test_limiter_enforces_configured_rate():
    clock = FakeClock()
    lim = _limiter(60, clock)  # 60/min -> one slot per second
    start = clock.now
    for _ in range(61):
        lim.acquire("10.0.0.5")
    # 61 requests at 60/min need 60 s of spacing (first slot is immediate).
    assert clock.now - start == pytest.approx(60.0)
    assert all(s == pytest.approx(1.0) for s in clock.sleeps)


def test_limiter_never_exceeds_rate_in_any_minute():
    clock = FakeClock()
    lim = _limiter(120, clock)
    stamps = []
    for _ in range(300):
        lim.acquire("t")
        stamps.append(clock.now)
    for i, t0 in enumerate(stamps):
        in_window = [t for t in stamps[i:] if t < t0 + 60.0]
        assert len(in_window) <= 120


def test_separate_targets_have_separate_budgets():
    clock = FakeClock()
    lim = _limiter(60, clock)
    lim.acquire("10.0.0.5")
    # A different target is not delayed by the first one's spend.
    assert lim.acquire("10.0.0.6") == 0.0
    assert clock.sleeps == []
    # The first target is still paced.
    assert lim.acquire("10.0.0.5") == pytest.approx(1.0)


def test_idle_time_does_not_bank_a_burst():
    clock = FakeClock()
    lim = _limiter(60, clock)
    lim.acquire("t")
    clock.now += 600  # idle for ten minutes
    lim.acquire("t")
    assert lim.acquire("t") == pytest.approx(1.0)


def test_no_target_is_not_charged():
    clock = FakeClock()
    lim = _limiter(1, clock)
    for _ in range(5):
        assert lim.acquire(None) == 0.0
        assert lim.acquire("") == 0.0
    assert clock.sleeps == []


def test_penalize_slows_only_that_target():
    clock = FakeClock()
    lim = _limiter(60, clock)
    lim.acquire("a")
    lim.penalize("a", 30)
    assert lim.acquire("b") == 0.0
    assert lim.acquire("a") == pytest.approx(31.0)


def test_rate_is_clamped_to_at_least_one():
    assert RateLimiter(0).rate_per_min == 1
    assert RateLimiter(-5).interval == pytest.approx(60.0)


# ───────────────────────── target extraction ─────────────────────────
@pytest.mark.parametrize(("cmd", "want"), [
    ("nmap -sV -F -T4 --open 10.0.0.5", "10.0.0.5"),
    ("curl -kisS --max-time 4 http://10.0.0.7:8080/api/users", "10.0.0.7"),
    ("nuclei -target https://Web.Lab:443 -silent", "web.lab"),
    ("enum4linux-ng -A 192.168.50.3", "192.168.50.3"),
    ("searchsploit --colour openssh", None),
    ("echo ok", None),
    ("", None),
])
def test_target_key_from_command(cmd, want):
    assert target_key_from_command(cmd) == want


def test_response_throttle_status():
    assert response_throttle_status("HTTP/1.1 429 Too Many Requests\r\n") == 429
    assert response_throttle_status("HTTP/2 503 \nretry-after: 5") == 503
    assert response_throttle_status("HTTP/1.1 200 OK") is None
    assert response_throttle_status("") is None


# ───────────────────────── Retry-After ─────────────────────────
def test_retry_after_seconds():
    assert parse_retry_after("5") == 5.0
    assert parse_retry_after(" 0 ") == 0.0
    assert parse_retry_after(7) == 7.0


def test_retry_after_http_date():
    now = datetime(2026, 11, 11, 12, 0, 0, tzinfo=timezone.utc)
    hdr = format_datetime(now + timedelta(seconds=20), usegmt=True)
    assert parse_retry_after(hdr, now=now) == pytest.approx(20.0)
    past = format_datetime(now - timedelta(seconds=20), usegmt=True)
    assert parse_retry_after(past, now=now) == 0.0


@pytest.mark.parametrize("junk", [None, "", "soon", "12abc", "nan", "Mon, 99 Foo 2026"])
def test_retry_after_garbage_returns_none(junk):
    assert parse_retry_after(junk) is None


def test_retry_after_huge_values_capped():
    assert parse_retry_after("999999") == 60.0
    assert parse_retry_after("1e300") == 60.0
    assert parse_retry_after("inf") == 60.0
    assert parse_retry_after("-10") == 0.0
    assert parse_retry_after("100", cap=15) == 15.0
    now = datetime(2026, 11, 11, tzinfo=timezone.utc)
    far = format_datetime(now + timedelta(days=30), usegmt=True)
    assert parse_retry_after(far, now=now) == 60.0


def test_backoff_delay_grows_and_is_capped():
    assert backoff_delay(0, jitter=False) == 0.5
    assert backoff_delay(3, jitter=False) == 4.0
    assert backoff_delay(50, jitter=False) == 60.0
    assert 0.25 <= backoff_delay(0, rand=lambda: 0.0) <= 0.5


# ───────────────────────── execute_with_backoff ─────────────────────────
def test_backoff_gives_up_after_max_retries():
    clock = FakeClock()
    calls = []

    def send():
        calls.append(1)
        return 429, None, "busy"

    with pytest.raises(Throttled) as ei:
        execute_with_backoff(send, max_retries=3, sleep=clock.sleep, rand=lambda: 1.0)
    assert len(calls) == 4          # first try + 3 retries
    assert len(clock.sleeps) == 3   # no sleep after the final attempt
    assert clock.sleeps == [0.5, 1.0, 2.0]
    assert ei.value.status == 429


def test_backoff_honors_retry_after_and_recovers():
    clock = FakeClock()
    seq = iter([(503, "7", None), (429, "9999", None), (200, None, "ok")])
    status, result = execute_with_backoff(lambda: next(seq), sleep=clock.sleep)
    assert (status, result) == (200, "ok")
    assert clock.sleeps == [7.0, 60.0]  # second Retry-After capped


def test_backoff_does_not_retry_other_errors():
    calls = []

    def send():
        calls.append(1)
        return 500, None, "boom"

    assert execute_with_backoff(send, sleep=lambda s: None) == (500, "boom")
    assert len(calls) == 1


# ───────────────────────── enforcement hooks ─────────────────────────
class _SpyLimiter(RateLimiter):
    def __init__(self):
        super().__init__(60, monotonic=lambda: 0.0, sleep=lambda s: None)
        self.acquired: list = []
        self.penalized: list = []

    def acquire(self, target, cost=1):
        self.acquired.append(target)
        return 0.0

    def penalize(self, target, cooldown_seconds):
        self.penalized.append((target, cooldown_seconds))


def _runner(scope, reply: str = "ok"):
    spy = _SpyLimiter()
    r = KaliRunner(scope=scope, cfg=scope.cfg, limiter=spy)
    r._exec = lambda command, timeout: CmdResult(rc=0, out=reply)  # no SSH
    return r, spy


def test_runner_default_limiter_uses_config_rate(scope):
    r = KaliRunner(scope=scope, cfg=scope.cfg)
    assert r.limiter.rate_per_min == 60  # conftest config


def test_runner_run_charges_target(scope):
    r, spy = _runner(scope)
    r.run(["nmap", "-sV", "10.0.0.5"])
    r.run(["curl", "-ksS", "http://10.0.0.7:8080/"])
    assert spy.acquired == ["10.0.0.5", "10.0.0.7"]


def test_runner_does_not_charge_non_target_commands(scope):
    r, spy = _runner(scope)
    r.run(["searchsploit", "--colour", "openssh"])
    r.run(["echo", "ok"])
    assert [t for t in spy.acquired if t] == []


def test_runner_blocked_command_is_not_charged(scope):
    r, spy = _runner(scope)
    res = r.run(["nmap", "8.8.8.8"])  # out of scope
    assert res.rc == 126
    assert spy.acquired == []


def test_runner_cools_down_throttling_target(scope):
    r, spy = _runner(scope, reply="HTTP/1.1 429 Too Many Requests\r\nRetry-After: 5")
    r.run(["curl", "-kisS", "http://10.0.0.5/api"])
    assert spy.penalized and spy.penalized[0][0] == "10.0.0.5"


def test_runner_actually_paces_with_real_limiter(scope):
    clock = FakeClock()
    r = KaliRunner(scope=scope, cfg=scope.cfg, limiter=_limiter(60, clock))
    r._exec = lambda command, timeout: CmdResult(rc=0, out="")
    for _ in range(3):
        r.run(["nmap", "10.0.0.5"])
    assert clock.sleeps == [pytest.approx(1.0), pytest.approx(1.0)]


class _Resp:
    def __init__(self, status, headers=None, body=None):
        self.status_code = status
        self.headers = headers or {}
        self._body = body or {}

    def json(self):
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


def test_aisec_request_path_is_rate_limited(monkeypatch):
    spy = _SpyLimiter()
    monkeypatch.setattr(aisec.requests, "post",
                        lambda *a, **k: _Resp(200, body={"message": {"content": "hi"}}))
    out = aisec._ask("http://10.0.0.8:11434", "m", "ollama", "hello", limiter=spy)
    assert out == "hi"
    assert spy.acquired == ["10.0.0.8"]


def test_aisec_throttled_is_error_not_pass(monkeypatch):
    spy = _SpyLimiter()
    calls = []

    def fake_post(*a, **k):
        calls.append(1)
        return _Resp(429, headers={"Retry-After": "0"})

    monkeypatch.setattr(aisec.requests, "post", fake_post)
    res = aisec.run_aisec("http://10.0.0.8:11434", "m", "ollama", limiter=spy,
                          include_crescendo=False)
    assert len(spy.acquired) == len(calls)  # every attempt, retries too, is paced
    assert res["results"]
    for r in res["results"]:
        assert r["error"] is True
        assert r["vulnerable"] is False
        assert "THROTTLED" in r["response"]
    assert "PASS" not in res["report"]
    assert res["posture"]["rating"] == "Inconclusive"
    assert res["posture"]["score"] == 0
