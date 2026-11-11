"""Per-target request pacing and adaptive backoff (stdlib only).

The ``scope.rate_limit_per_min`` setting is a courtesy limit: it keeps OniOps
from hammering a single authorized target faster than the operator intended.

What one *unit* means here is deliberate and narrow: **one command or HTTP
request sent toward a target counts as one unit.** It is NOT a packet budget.
A single ``nmap``/``nikto``/``nuclei`` command emits many packets on its own,
so the limit bounds how often OniOps *launches* work against a host, not the
traffic each launched tool then generates. Commands that do not touch a target
(local bookkeeping, ``searchsploit`` lookups, an ``echo`` health check) are not
charged at all.

``RateLimiter`` paces each target independently (separate targets have separate
budgets) with evenly spaced slots (a leaky-bucket / GCRA with no burst) and a
blocking wait -- ``acquire`` sleeps until the next slot and never raises. The
clock and sleep are injectable so tests drive it with a fake clock and never
sleep for real.
"""

from __future__ import annotations

import random
import re
import threading
import time
from collections.abc import Callable
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

# Pull the host/IP a shell command is aimed at. A URL host wins (covers curl,
# httpx, nuclei, whatweb, ...); otherwise the first bare IPv4 (nmap, enum4linux,
# sslscan, ...). Anything else -> no target -> not charged.
_URL_HOST_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9+.\-]*://([^/\s:]+)")
_IPV4_RE = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3})\b")
# A 429/503 status line in curl-style output, used for per-target cool-down.
_HTTP_THROTTLE_RE = re.compile(r"HTTP/[\d.]+\s+(429|503)\b")

# Retry-After / backoff are capped so a hostile or broken server cannot park a
# run for an unbounded time.
DEFAULT_BACKOFF_CAP = 60.0


def target_key_from_command(command: str) -> str | None:
    """Return the host/IP a command is aimed at, or ``None`` if it touches no
    target. One command toward a target = one unit charged to that target."""
    if not command:
        return None
    m = _URL_HOST_RE.search(command)
    if m:
        return m.group(1).lower()
    m = _IPV4_RE.search(command)
    if m:
        return m.group(1)
    return None


def response_throttle_status(output: str) -> int | None:
    """Return 429/503 if a curl-style response body shows that status line,
    else ``None``. Used to trigger a per-target cool-down."""
    if not output:
        return None
    m = _HTTP_THROTTLE_RE.search(output)
    return int(m.group(1)) if m else None


def parse_retry_after(
    value: object,
    *,
    cap: float = DEFAULT_BACKOFF_CAP,
    now: datetime | None = None,
) -> float | None:
    """Parse an HTTP ``Retry-After`` value into a delay in seconds, clamped to
    ``[0, cap]``.

    Accepts an integer/float number of seconds or an HTTP-date. Returns ``None``
    for a missing or unparseable value (the caller then falls back to its own
    backoff). Negative, NaN and absurdly large values are handled safely.
    """
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None
    try:
        secs = float(s)
    except ValueError:
        try:
            dt = parsedate_to_datetime(s)
        except (TypeError, ValueError, OverflowError):
            return None
        if dt is None:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        base = now or datetime.now(timezone.utc)
        secs = (dt - base).total_seconds()
    if secs != secs:  # NaN
        return None
    if secs in (float("inf"), float("-inf")):
        return cap if secs > 0 else 0.0
    return max(0.0, min(cap, secs))


def backoff_delay(
    attempt: int,
    *,
    base: float = 0.5,
    cap: float = DEFAULT_BACKOFF_CAP,
    jitter: bool = True,
    rand: Callable[[], float] = random.random,
) -> float:
    """Exponential backoff (``base * 2**attempt``) capped at ``cap``, with
    optional full-ish jitter in ``[0.5, 1.0] x`` the computed delay."""
    delay = min(cap, base * (2 ** max(0, attempt)))
    if jitter:
        delay = delay * (0.5 + 0.5 * rand())
    return delay


class Throttled(Exception):
    """Raised when a target keeps answering 429/503 past the retry budget."""

    def __init__(self, status: int | None, attempts: int):
        self.status = status
        self.attempts = attempts
        super().__init__(
            f"target throttling (HTTP {status}) after {attempts} retries"
        )


def execute_with_backoff(
    send: Callable[[], tuple[int, object, object]],
    *,
    max_retries: int = 3,
    cap: float = DEFAULT_BACKOFF_CAP,
    sleep: Callable[[float], None] = time.sleep,
    rand: Callable[[], float] = random.random,
    now_fn: Callable[[], datetime] | None = None,
) -> tuple[int, object]:
    """Call ``send`` and retry on HTTP 429/503 with adaptive backoff.

    ``send`` returns ``(status_code, retry_after_header, result)``. On 429/503,
    honor ``Retry-After`` (seconds or HTTP-date, capped at ``cap``) else use
    jittered exponential backoff, retrying up to ``max_retries`` times. Any
    other status returns ``(status, result)`` immediately. If the target is
    still throttling after the budget, raise :class:`Throttled` -- the caller
    must record a throttled outcome, never a pass.
    """
    last_status: int | None = None
    for attempt in range(max_retries + 1):
        status, retry_after, result = send()
        if status not in (429, 503):
            return status, result
        last_status = status
        if attempt >= max_retries:
            break
        delay = parse_retry_after(retry_after, cap=cap, now=(now_fn() if now_fn else None))
        if delay is None:
            delay = backoff_delay(attempt, cap=cap, rand=rand)
        sleep(delay)
    raise Throttled(last_status, max_retries)


class RateLimiter:
    """Evenly spaced per-target request limiter (leaky-bucket / GCRA, no burst).

    Honors ``rate_per_min`` requests per minute *per target*; separate targets
    have independent budgets. ``acquire`` blocks (sleeps) until the target's
    next slot and never raises. One unit = one command/request sent toward a
    target -- see the module docstring; this does not bound packets. The clock
    and sleep are injectable so tests use a fake clock and do not sleep.
    """

    def __init__(
        self,
        rate_per_min: int,
        *,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.rate_per_min = max(1, int(rate_per_min))
        self.interval = 60.0 / self.rate_per_min
        self._monotonic = monotonic
        self._sleep = sleep
        self._lock = threading.Lock()
        self._next_allowed: dict[str, float] = {}

    def acquire(self, target: str | None, cost: int = 1) -> float:
        """Block until ``target`` may send again, then reserve its slot. Returns
        the number of seconds waited. A falsy target is never charged."""
        if not target:
            return 0.0
        cost = max(1, int(cost))
        with self._lock:
            now = self._monotonic()
            slot = self._next_allowed.get(target, now)
            if slot < now:
                slot = now
            self._next_allowed[target] = slot + self.interval * cost
        wait = slot - now
        if wait > 0:
            self._sleep(wait)
        return max(0.0, wait)

    def penalize(self, target: str | None, cooldown_seconds: float) -> None:
        """Push a target's next slot further out after it signalled throttling
        (HTTP 429/503), slowing that target for a while without touching others."""
        if not target or cooldown_seconds <= 0:
            return
        with self._lock:
            now = self._monotonic()
            base = max(self._next_allowed.get(target, now), now)
            self._next_allowed[target] = base + float(cooldown_seconds)
