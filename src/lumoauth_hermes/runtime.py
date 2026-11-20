"""Runtime state of the Guard: snapshot, taint, receipts, usage, and the background worker.

Network work happens on one daemon thread (``Worker``), never on Hermes's
agent thread, except where SPEC requires an answer before the call runs
(a missing snapshot, server-mode Ask, LumoAuth push approvals).
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from collections import Counter, deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from .client import AgentClient, AuthError, LumoAuthError
from .config import GuardHome
from .decide import SnapshotView

logger = logging.getLogger("lumoauth_hermes")

MAX_QUEUE = 1000
BATCH = 50
FLUSH_AT = 20
FLUSH_SECONDS = 5.0
PENDING_SECONDS = 600.0
USAGE_SECONDS = 60.0
MAX_BACKOFF = 300.0
#: Receipts older than this are not sent: the server accepts the last 24 hours only.
MAX_RECEIPT_AGE = timedelta(hours=23)

_ERROR_CODE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
_SERVER_ID = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")
_AUDIT = re.compile(r"^[0-9a-f]{16}$")
DECISIONS = ("allowed", "approved", "denied", "refused", "expired", "blocked")
NOT_RUN = ("denied", "refused", "expired", "blocked")


def utc_now() -> datetime:
    return datetime.now(UTC)


def iso(moment: datetime | None = None) -> str:
    moment = moment or utc_now()
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def error_code(value: Any) -> str | None:
    """A short code the server accepts, or None."""
    if not isinstance(value, str):
        return None
    code = re.sub(r"[^A-Za-z0-9_.:-]", "_", value.strip())[:64]
    return code if _ERROR_CODE.match(code) else None


def valid_receipt(receipt: dict[str, Any], now: datetime | None = None) -> bool:
    """The server's own checks (AgentToolCallReporter), so that one bad entry never sinks a batch."""
    allowed = {"tool", "server_id", "decision", "outcome", "duration_ms", "arguments_sha256", "audit_id",
               "occurred_at", "error_code"}
    if set(receipt) - allowed:
        return False
    tool = receipt.get("tool")
    if not isinstance(tool, str) or not tool or len(tool) > 200:
        return False
    if receipt.get("decision") not in DECISIONS:
        return False
    outcome = receipt.get("outcome")
    if outcome is not None and (outcome not in ("succeeded", "failed", "not_run") or (
            outcome != "not_run" and receipt["decision"] in NOT_RUN)):
        return False
    if "server_id" in receipt and not _SERVER_ID.match(str(receipt["server_id"])):
        return False
    duration = receipt.get("duration_ms")
    if duration is not None and (not isinstance(duration, int) or isinstance(duration, bool)
                                 or not 0 <= duration <= 86_400_000):
        return False
    if "arguments_sha256" in receipt and not _SHA.match(str(receipt["arguments_sha256"])):
        return False
    if "audit_id" in receipt and not _AUDIT.match(str(receipt["audit_id"])):
        return False
    if "error_code" in receipt and not _ERROR_CODE.match(str(receipt["error_code"])):
        return False
    occurred = receipt.get("occurred_at")
    if occurred is not None:
        try:
            moment = datetime.strptime(str(occurred), "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
        except ValueError:
            return False
        if (now or utc_now()) - moment > MAX_RECEIPT_AGE:
            return False
    return True


# ── Snapshot ────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Snapshot:
    capabilities: tuple[str, ...]
    status: str
    agent_id: str
    fetched_at: float  # time.monotonic()
    fetched_wall: float  # time.time()


class SnapshotStore:
    """The agent's capabilities as LumoAuth last confirmed them (SPEC §7.2)."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self.snapshot: Snapshot | None = None
        self.last_error: str | None = None
        self.last_attempt: float = 0.0
        self.last_success_wall: float = 0.0

    def clear(self, reason: str) -> None:
        with self._lock:
            self.snapshot = None
            self.last_error = reason

    def view(self) -> SnapshotView | None:
        snap = self.snapshot
        if snap is None:
            return None
        return SnapshotView(snap.capabilities, snap.status, max(0.0, self._clock() - snap.fetched_at))

    def age(self) -> float | None:
        snap = self.snapshot
        return None if snap is None else max(0.0, self._clock() - snap.fetched_at)

    def refresh(self, client: AgentClient, timeout: float) -> bool:
        """Fetch ``/agents/me``. Auth failures clear the snapshot; network errors keep it."""
        self.last_attempt = self._clock()
        try:
            body = client.me(timeout=timeout)
        except AuthError as exc:
            client.invalidate_token()
            self.clear(str(exc))
            return False
        except LumoAuthError as exc:
            with self._lock:
                self.last_error = str(exc)
            return False
        identity = body.get("identity") if isinstance(body.get("identity"), dict) else {}
        caps = body.get("capabilities")
        capabilities = tuple(c for c in caps if isinstance(c, str)) if isinstance(caps, list) else ()
        status = identity.get("status") if isinstance(identity.get("status"), str) else "unknown"
        snap = Snapshot(capabilities, status, str(identity.get("agent_id") or ""), self._clock(), time.time())
        with self._lock:
            self.snapshot = snap
            self.last_error = None if status == "active" else f"agent status is {status}"
            self.last_success_wall = snap.fetched_wall
        return True


# ── Taint (SPEC §6.3) ───────────────────────────────────────────────────────

class TaintTracker:
    """Sessions that took in untrusted content, in memory only."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._marks: dict[str, float] = {}

    def mark(self, keys: Iterable[str]) -> None:
        now = self._clock()
        with self._lock:
            for key in keys:
                if key:
                    self._marks[key] = now
            if len(self._marks) > 5000:
                for old in sorted(self._marks, key=self._marks.get)[:1000]:  # type: ignore[arg-type]
                    del self._marks[old]

    def is_tainted(self, keys: Iterable[str], window_seconds: float) -> bool:
        now = self._clock()
        with self._lock:
            return any(key and key in self._marks and now - self._marks[key] <= window_seconds for key in keys)

    def count(self, window_seconds: float) -> int:
        now = self._clock()
        with self._lock:
            return sum(1 for t in self._marks.values() if now - t <= window_seconds)


# ── Receipts (SPEC §7.4) ────────────────────────────────────────────────────

@dataclass
class Pending:
    """A receipt that waits for the post-tool-call hook."""

    receipt: dict[str, Any]
    created: float
    tool_call_id: str
    match_key: tuple[str, str, str]
    host_approval: bool = False
    rule_key: str = ""
    choice: str | None = None
    ingests_untrusted: bool = False
    taint_keys: tuple[str, ...] = ()
    send: bool = True
    #: SPEC §4.1a: the pre-decision to keep once a person approves a dispatcher call.
    predecision: tuple[str, str, str] | None = None


class ReceiptQueue:
    """Receipts waiting to be sent: at most 1,000, oldest dropped first."""

    def __init__(self, limit: int = MAX_QUEUE) -> None:
        self.limit = limit
        self._lock = threading.Lock()
        self._queue: deque[dict[str, Any]] = deque()
        self._pending: dict[int, Pending] = {}
        self._next = 0
        self.dropped = 0
        self.sent = 0
        self.rejected = 0
        self.wake = threading.Event()

    def __len__(self) -> int:
        with self._lock:
            return len(self._queue)

    @property
    def pending_count(self) -> int:
        with self._lock:
            return len(self._pending)

    def add(self, receipt: dict[str, Any]) -> None:
        with self._lock:
            self._queue.append(receipt)
            while len(self._queue) > self.limit:
                self._queue.popleft()
                self.dropped += 1
            if len(self._queue) >= FLUSH_AT:
                self.wake.set()

    def add_pending(self, pending: Pending) -> None:
        with self._lock:
            self._next += 1
            self._pending[self._next] = pending
            if len(self._pending) > self.limit:
                oldest = min(self._pending)
                self._queue.append(self._pending.pop(oldest).receipt)

    def find_pending(self, tool_call_id: str, match_key: tuple[str, str, str], *, pop: bool) -> Pending | None:
        with self._lock:
            chosen = None
            if tool_call_id:
                chosen = next((k for k, p in self._pending.items() if p.tool_call_id == tool_call_id), None)
            if chosen is None:
                chosen = next((k for k, p in self._pending.items() if p.match_key == match_key
                               and (not tool_call_id or not p.tool_call_id)), None)
            if chosen is None:
                return None
            return self._pending.pop(chosen) if pop else self._pending[chosen]

    def find_approval(self, tool_call_id: str, rule_key: str) -> Pending | None:
        with self._lock:
            for pending in reversed(list(self._pending.values())):
                if not pending.host_approval:
                    continue
                if tool_call_id and pending.tool_call_id == tool_call_id:
                    return pending
                if rule_key and pending.rule_key == rule_key and pending.choice is None:
                    return pending
            return None

    def expire_pending(self, now: float) -> int:
        """Send receipts whose call never completed, without an outcome (after 10 minutes)."""
        with self._lock:
            old = [k for k, p in self._pending.items() if now - p.created >= PENDING_SECONDS]
            for key in old:
                pending = self._pending.pop(key)
                if not pending.send:
                    continue
                receipt = pending.receipt
                if pending.host_approval:
                    receipt["decision"] = {"once": "approved", "session": "approved", "always": "approved",
                                           "deny": "refused"}.get(pending.choice or "", "expired")
                self._queue.append(receipt)
            return len(old)

    def take(self, count: int = BATCH) -> list[dict[str, Any]]:
        with self._lock:
            batch = []
            while self._queue and len(batch) < count:
                batch.append(self._queue.popleft())
            return batch

    def put_back(self, batch: list[dict[str, Any]]) -> None:
        with self._lock:
            for receipt in reversed(batch):
                self._queue.appendleft(receipt)
            while len(self._queue) > self.limit:
                self._queue.popleft()
                self.dropped += 1

    def drain_all(self) -> list[dict[str, Any]]:
        with self._lock:
            items = list(self._queue) + [p.receipt for p in self._pending.values() if p.send]
            self._queue.clear()
            self._pending.clear()
            return items


def send_receipts(client: AgentClient, queue: ReceiptQueue, timeout: float = 10.0) -> float | None:
    """Send one batch. Returns None when done, or the seconds to wait before trying again."""
    batch = [r for r in queue.take(BATCH)]
    if not batch:
        return None
    now = utc_now()
    good = [r for r in batch if valid_receipt(r, now)]
    if len(good) < len(batch):
        queue.rejected += len(batch) - len(good)
        logger.warning("LumoAuth Guard dropped %d receipt(s) that LumoAuth would refuse", len(batch) - len(good))
    if not good:
        return None
    try:
        response = client.report_tool_calls(good, timeout=timeout)
    except LumoAuthError as exc:
        queue.put_back(good)
        return exc.retry_after or FLUSH_SECONDS
    if response.status_code == 200:
        queue.sent += len(good)
        return None
    if response.status_code == 400:
        queue.rejected += len(good)
        try:
            detail = response.json().get("error_description", "")
        except ValueError:
            detail = ""
        logger.error("LumoAuth refused %d receipt(s) (a bug in lumoauth-hermes): %s", len(good), str(detail)[:300])
        return None
    queue.put_back(good)
    retry = response.headers.get("Retry-After")
    try:
        return max(1.0, min(float(retry), MAX_BACKOFF)) if retry else FLUSH_SECONDS
    except ValueError:
        return FLUSH_SECONDS


# ── Pre-decisions of dispatcher calls (SPEC §4.1a) ─────────────────────────

PREDECISION_SECONDS = 60.0


class PreDecisions:
    """Allowed dispatched calls, kept 60 s for the host's own hook on the inner call; each is used once."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._items: dict[tuple[str, str, str], list[float]] = {}

    def add(self, key: tuple[str, str, str]) -> None:
        now = self._clock()
        with self._lock:
            self._items = {k: [t for t in v if t > now] for k, v in self._items.items() if any(t > now for t in v)}
            self._items.setdefault(key, []).append(now + PREDECISION_SECONDS)

    def take(self, key: tuple[str, str, str]) -> bool:
        now = self._clock()
        with self._lock:
            times = [t for t in self._items.get(key, []) if t > now]
            if not times:
                self._items.pop(key, None)
                return False
            times.pop(0)
            if times:
                self._items[key] = times
            else:
                self._items.pop(key, None)
            return True


# ── Usage (SPEC §7.6) ───────────────────────────────────────────────────────

class UsageMeter:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.tokens = 0
        self.reported = 0

    def add(self, tokens: Any) -> None:
        if isinstance(tokens, bool) or not isinstance(tokens, (int, float)) or tokens <= 0:
            return
        with self._lock:
            self.tokens = min(self.tokens + int(tokens), 100_000_000)

    def take(self) -> int:
        with self._lock:
            value, self.tokens = self.tokens, 0
            return value

    def put_back(self, tokens: int) -> None:
        self.add(tokens)


# ── Persistence of unsent receipts across restarts ──────────────────────────

def _locked(handle: Any) -> None:
    try:
        import fcntl

        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
    except (ImportError, OSError):
        pass


def adopt_queue_file(home: GuardHome) -> list[dict[str, Any]]:
    """Take over receipts that an earlier process could not send (and empty the file)."""
    path = home.queue_path
    if not path.exists():
        return []
    receipts: list[dict[str, Any]] = []
    try:
        with open(path, "r+", encoding="utf-8") as handle:
            _locked(handle)
            for line in handle.read().splitlines()[-MAX_QUEUE:]:
                try:
                    value = json.loads(line)
                except ValueError:
                    continue
                if isinstance(value, dict) and valid_receipt(value):
                    receipts.append(value)
            handle.seek(0)
            handle.truncate()
    except OSError:
        return []
    return receipts


def save_queue_file(home: GuardHome, receipts: list[dict[str, Any]]) -> None:
    """Append unsent receipts for the next process (mode 0600, bounded)."""
    if not receipts:
        return
    try:
        home.ensure()
        fd = os.open(home.queue_path, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "r+", encoding="utf-8") as handle:
            _locked(handle)
            handle.seek(0)
            existing = handle.read().splitlines()
            lines = (existing + [json.dumps(r, separators=(",", ":")) for r in receipts])[-MAX_QUEUE:]
            handle.seek(0)
            handle.truncate()
            handle.write("\n".join(lines) + "\n")
    except OSError:
        logger.debug("could not save unsent receipts", exc_info=True)


@dataclass
class RecentDecision:
    at: str
    tool: str
    decision: str
    reason: str


@dataclass
class RuntimeCounters:
    counts: Counter = field(default_factory=Counter)
    recent: deque = field(default_factory=lambda: deque(maxlen=20))

    def record(self, tool: str, decision: str, reason: str) -> None:
        self.counts[decision] += 1
        self.recent.append(RecentDecision(iso(), tool[:200], decision, reason))
