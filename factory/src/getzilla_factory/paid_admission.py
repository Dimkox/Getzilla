"""Closed paid-operation authority and accounting in the existing landing store.

Only the owning server installs authority. Request data, credentials and models
cannot install it. Amounts use integer micro-USD. Ambiguous spend never expires.
This local store does not prove deployment-wide or native-host enforcement.
"""

from dataclasses import asdict, dataclass
from contextvars import ContextVar

import hashlib
import math
import re

from .contracts import canonical_json
from .landing_contracts import strict_json_object
from .landing_provider import LandingProviderError

SHARED_DISPATCH_GUARD = ContextVar("shared_landing_dispatch_guard", default=None)

OPERATIONS = frozenset({"paid-inference", "paid-image", "paid-video"})
from importlib.resources import files

SCHEMA = (
    files("getzilla_factory").joinpath("resources/landing-sqlite-003-paid-admission.sql").read_text(encoding="utf-8")
)

COLUMNS = {
    "paid_accounts": (("account_id", "TEXT", 1, 1), ("authority", "BLOB", 1, 0), ("disabled", "INTEGER", 1, 0)),
    "paid_tasks": (("account_id", "TEXT", 1, 1), ("task_id", "TEXT", 1, 2), ("authority", "BLOB", 1, 0)),
    "paid_prices": (
        ("account_id", "TEXT", 1, 1),
        ("provider_id", "TEXT", 1, 2),
        ("model_id", "TEXT", 1, 3),
        ("price", "BLOB", 1, 0),
    ),
    "paid_reservations": tuple(
        (n, t, nullable, pk)
        for n, t, nullable, pk in [
            ("reservation_id", "TEXT", 1, 1),
            ("account_id", "TEXT", 1, 0),
            ("task_id", "TEXT", 1, 0),
            ("request_digest", "TEXT", 1, 0),
            ("provider_id", "TEXT", 1, 0),
            ("model_id", "TEXT", 1, 0),
            ("operation", "TEXT", 1, 0),
            ("cost_micros", "INTEGER", 1, 0),
            ("input_units", "INTEGER", 1, 0),
            ("output_units", "INTEGER", 1, 0),
            ("state", "TEXT", 1, 0),
            ("created_at", "REAL", 1, 0),
            ("observed_input", "INTEGER", 0, 0),
            ("observed_output", "INTEGER", 0, 0),
        ]
    ),
}


def _deny(code):
    raise LandingProviderError(code)


def _identifier(value):
    return isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}", value) is not None


def _positive(value):
    return type(value) is int and 0 < value <= 2**53


@dataclass(frozen=True)
class PaidAccountV1:
    owner_id: str
    account_id: str
    tenant_id: str
    scheduler_id: str
    policy_version: str
    starts_at: float
    expires_at: float
    cost_limit_micros: int
    max_attempts: int
    max_inflight: int
    max_per_minute: int

    def validate(self):
        if not all(
            _identifier(v)
            for v in (self.owner_id, self.account_id, self.tenant_id, self.scheduler_id, self.policy_version)
        ):
            _deny("paid_authority_invalid")
        if not all(
            _positive(v) for v in (self.cost_limit_micros, self.max_attempts, self.max_inflight, self.max_per_minute)
        ):
            _deny("paid_authority_invalid")
        if self.max_attempts > 10000 or self.max_inflight > 1000 or self.max_per_minute > 10000:
            _deny("paid_authority_invalid")
        if (
            any(type(v) not in (int, float) or not math.isfinite(v) for v in (self.starts_at, self.expires_at))
            or not 0 < self.expires_at - self.starts_at <= 86400
        ):
            _deny("paid_authority_invalid")


@dataclass(frozen=True)
class PaidTaskV1:
    task_id: str
    repository_id: str
    route_id: str
    source_head: str
    source_tree: str
    source_identity: str
    credential_ref: str
    cost_limit_micros: int
    max_attempts: int
    max_input_units: int
    max_output_units: int
    scope: tuple[tuple[str, str, str], ...]
    input_digest: str
    deadline_at: float

    def validate(self):
        if type(self.deadline_at) not in (int, float) or not math.isfinite(self.deadline_at) or self.deadline_at <= 0:
            _deny("paid_authority_invalid")
        if not all(
            _identifier(v) for v in (self.task_id, self.repository_id, self.route_id, self.credential_ref)
        ) or not all(
            _positive(v)
            for v in (self.cost_limit_micros, self.max_attempts, self.max_input_units, self.max_output_units)
        ):
            _deny("paid_authority_invalid")
        if any(
            not isinstance(v, str) or re.fullmatch(r"[0-9a-f]{" + str(n) + "}", v) is None
            for v, n in [
                (self.source_head, 40),
                (self.source_tree, 40),
                (self.source_identity, 64),
                (self.input_digest, 64),
            ]
        ):
            _deny("paid_authority_invalid")
        if not self.scope or any(
            len(item) != 3 or not _identifier(item[0]) or not _identifier(item[1]) or item[2] not in OPERATIONS
            for item in self.scope
        ):
            _deny("paid_authority_invalid")


@dataclass(frozen=True)
class PaidPriceV1:
    provider_id: str
    model_id: str
    price_version: str
    input_micros_per_unit: int
    output_micros_per_unit: int
    media_kinds: tuple[str, ...] = ("text",)
    billable_input_ceiling: int | None = None

    def validate(self):
        if not all(_identifier(v) for v in (self.provider_id, self.model_id, self.price_version)) or not all(
            _positive(v) for v in (self.input_micros_per_unit, self.output_micros_per_unit)
        ):
            _deny("paid_price_invalid")
        if not self.media_kinds or any(v not in {"text", "docx", "image", "audio", "pdf"} for v in self.media_kinds):
            _deny("paid_price_invalid")
        if any(v != "text" for v in self.media_kinds) and not _positive(self.billable_input_ceiling):
            _deny("paid_price_invalid")


class PaidExecutionAdmission:
    def __init__(self, store, account_id, task_id, credential_ref, source_identity, *, dry_run=False):
        from .landing_sqlite_store import SQLiteLandingJobStore

        if type(store) is not SQLiteLandingJobStore or type(dry_run) is not bool:
            _deny("paid_authority_invalid")
        self.store = store
        self.account_id = account_id
        self.task_id = task_id
        self.credential_ref = credential_ref
        self.source_identity = source_identity
        self.dry_run = dry_run

    def input_ceiling(self, provider, model, media_kind, encoded_size):
        with self.store._lock:
            self.store._ensure_open()
            row = self.store._connection.execute(
                "SELECT price FROM paid_prices WHERE account_id=? AND provider_id=? AND model_id=?",
                (self.account_id, provider, model),
            ).fetchone()
            if row is None:
                _deny("paid_price_unknown")
            price = PaidPriceV1(**strict_json_object(row[0]))
            price.validate()
            if media_kind not in price.media_kinds:
                _deny("paid_media_price_unknown")
            return encoded_size if media_kind == "text" else price.billable_input_ceiling

    def reserve(self, provider, model, operation, digest, input_units, output_units):
        if self.dry_run:
            _deny("paid_dry_run")
        return self.store.reserve_paid(
            self.account_id,
            self.task_id,
            self.credential_ref,
            self.source_identity,
            provider,
            model,
            operation,
            digest,
            input_units,
            output_units,
        )

    def dispatch(self, reservation, input_digest, request_digest=None, provider=None, model=None):
        guard = SHARED_DISPATCH_GUARD.get()
        if guard is not None:
            guard(self, input_digest, provider, model)
        return dispatch(
            self.store, self.account_id, self.task_id, reservation, input_digest, request_digest, provider, model
        )

    def unknown_if_dispatched(self, reservation):
        with self.store._transaction():
            self.store._connection.execute(
                "UPDATE paid_reservations SET state='unknown' WHERE reservation_id=? AND account_id=? AND task_id=? AND state='dispatching'",
                (reservation, self.account_id, self.task_id),
            )

    def finish(self, reservation, usage=None):
        finish(self.store, self.account_id, self.task_id, reservation, usage)


def install(store, account, task, prices):
    if type(account) is not PaidAccountV1 or type(task) is not PaidTaskV1 or not prices:
        _deny("paid_authority_invalid")
    account.validate()
    task.validate()
    if not account.starts_at < task.deadline_at <= account.expires_at:
        _deny("paid_authority_invalid")
    for price in prices:
        if type(price) is not PaidPriceV1:
            _deny("paid_price_invalid")
        price.validate()
    with store._transaction():
        if (
            store._connection.execute("SELECT count(*) FROM paid_accounts").fetchone()[0] >= 10000
            and not store._connection.execute(
                "SELECT 1 FROM paid_accounts WHERE account_id=?", (account.account_id,)
            ).fetchone()
        ):
            _deny("paid_authority_capacity")
        if (
            store._connection.execute("SELECT count(*) FROM paid_tasks").fetchone()[0] >= 10000
            and not store._connection.execute(
                "SELECT 1 FROM paid_tasks WHERE account_id=? AND task_id=?", (account.account_id, task.task_id)
            ).fetchone()
        ):
            _deny("paid_authority_capacity")
        # Account/key/scheduler rotation cannot create a second overlapping
        # allowance for the same owner or tenant in this authority store.
        for account_id, raw in store._connection.execute("SELECT account_id,authority FROM paid_accounts"):
            prior = PaidAccountV1(**strict_json_object(raw))
            prior.validate()
            if (
                account_id != account.account_id
                and (prior.owner_id == account.owner_id or prior.tenant_id == account.tenant_id)
                and max(prior.starts_at, account.starts_at) < min(prior.expires_at, account.expires_at)
            ):
                _deny("paid_account_overlap")
        for table, values, blob in [
            ("paid_accounts", (account.account_id,), canonical_json(asdict(account))),
            ("paid_tasks", (account.account_id, task.task_id), canonical_json(asdict(task))),
        ]:
            query = ("SELECT authority FROM paid_accounts WHERE account_id=?"
                     if table == "paid_accounts" else
                     "SELECT authority FROM paid_tasks WHERE account_id=? AND task_id=?")
            old = store._connection.execute(query, values).fetchone()
            if old is not None and old[0] != blob:
                _deny("paid_authority_conflict")
            if old is None:
                if table == "paid_accounts":
                    store._connection.execute("INSERT INTO paid_accounts VALUES(?,?,0)", (*values, blob))
                else:
                    store._connection.execute("INSERT INTO paid_tasks VALUES(?,?,?)", (*values, blob))
        for price in prices:
            blob = canonical_json(asdict(price))
            key = (account.account_id, price.provider_id, price.model_id)
            old = store._connection.execute(
                "SELECT price FROM paid_prices WHERE account_id=? AND provider_id=? AND model_id=?", key
            ).fetchone()
            if old is not None and old[0] != blob:
                _deny("paid_price_conflict")
            store._connection.execute("INSERT OR IGNORE INTO paid_prices VALUES(?,?,?,?)", (*key, blob))


def _authority(store, account_id, task_id):
    row = store._connection.execute(
        "SELECT authority,disabled FROM paid_accounts WHERE account_id=?", (account_id,)
    ).fetchone()
    task = store._connection.execute(
        "SELECT authority FROM paid_tasks WHERE account_id=? AND task_id=?", (account_id, task_id)
    ).fetchone()
    if row is None or task is None:
        _deny("paid_authority_required")
    account = PaidAccountV1(**strict_json_object(row[0]))
    task = PaidTaskV1(**strict_json_object(task[0]))
    account.validate()
    task.validate()
    # Callers commit one fresh time observation before entering this possibly
    # failing transaction. Never observe a later clock only to roll it back.
    clock = store._connection.execute("SELECT highwater FROM shared_control_clock WHERE singleton=1").fetchone()
    if clock is None:
        _deny("paid_authority_clock_required")
    now = clock[0]
    if row[1] != 0:
        _deny("paid_disabled")
    if not account.starts_at <= now < min(account.expires_at, task.deadline_at):
        _deny("paid_expired")
    return account, task, now


def reserve(
    store,
    account_id,
    task_id,
    credential_ref,
    source_identity,
    provider,
    model,
    operation,
    digest,
    input_units,
    output_units,
):
    if (
        not isinstance(digest, str)
        or re.fullmatch("[0-9a-f]{64}", digest) is None
        or not all(_positive(v) for v in (input_units, output_units))
    ):
        _deny("paid_request_invalid")
    store.authority_time()
    with store._transaction():
        account, task, now = _authority(store, account_id, task_id)
        if credential_ref != task.credential_ref or source_identity != task.source_identity:
            _deny("paid_scope")
        if [provider, model, operation] not in [list(s) for s in task.scope] or operation != "paid-inference":
            _deny("paid_scope")
        if input_units > task.max_input_units or output_units > task.max_output_units:
            _deny("paid_units")
        row = store._connection.execute(
            "SELECT price FROM paid_prices WHERE account_id=? AND provider_id=? AND model_id=?",
            (account_id, provider, model),
        ).fetchone()
        if row is None:
            _deny("paid_price_unknown")
        price = PaidPriceV1(**strict_json_object(row[0]))
        price.validate()
        cost = input_units * price.input_micros_per_unit + output_units * price.output_micros_per_unit
        duplicate = store._connection.execute(
            "SELECT reservation_id FROM paid_reservations WHERE account_id=? AND task_id=? AND request_digest=? AND provider_id=? AND model_id=? AND operation=?",
            (account_id, task_id, digest, provider, model, operation),
        ).fetchone()
        if duplicate is not None:
            _deny("paid_replay")
        rows = store._connection.execute(
            "SELECT task_id,cost_micros,state,created_at FROM paid_reservations WHERE account_id=?", (account_id,)
        ).fetchall()
        if any(t == task_id and state in ("dispatching", "unknown") for t, c, state, at in rows):
            _deny("paid_unknown")
        own = [r for r in rows if r[0] == task_id]
        if (
            sum(r[1] for r in rows) + cost > account.cost_limit_micros
            or sum(r[1] for r in own) + cost > task.cost_limit_micros
            or len(rows) >= account.max_attempts
            or len(own) >= task.max_attempts
            or sum(r[2] in ("reserved", "dispatching", "unknown") for r in rows) >= account.max_inflight
            or sum(r[3] > now - 60 for r in rows) >= account.max_per_minute
        ):
            _deny("paid_budget")
        reservation = hashlib.sha256(
            canonical_json([account_id, task_id, digest, provider, model, operation])
        ).hexdigest()
        store._connection.execute(
            "INSERT INTO paid_reservations VALUES(?,?,?,?,?,?,?,?,?,?,?, ?,NULL,NULL)",
            (
                reservation,
                account_id,
                task_id,
                digest,
                provider,
                model,
                operation,
                cost,
                input_units,
                output_units,
                "reserved",
                now,
            ),
        )
        return reservation


def dispatch(store, account_id, task_id, reservation, input_digest, request_digest, provider, model):
    store.authority_time()
    with store._transaction():
        account, task, now = _authority(store, account_id, task_id)
        if input_digest != task.input_digest:
            _deny("paid_scope")
        row = store._connection.execute(
            "SELECT state,request_digest,provider_id,model_id FROM paid_reservations WHERE reservation_id=? AND account_id=? AND task_id=?",
            (reservation, account_id, task_id),
        ).fetchone()
        if row is None or row[0] != "reserved":
            _deny("paid_replay")
        if tuple(row[1:]) != (request_digest, provider, model):
            _deny("paid_scope")
        if store._connection.execute(
            "SELECT 1 FROM paid_reservations WHERE account_id=? AND task_id=? AND reservation_id<>? AND state IN ('dispatching','unknown') LIMIT 1",
            (account_id, task_id, reservation),
        ).fetchone():
            _deny("paid_unknown")
        store._connection.execute(
            "UPDATE paid_reservations SET state='dispatching' WHERE reservation_id=?", (reservation,)
        )
        return min(account.expires_at, task.deadline_at) - now


def finish(store, account_id, task_id, reservation, usage):
    with store._transaction():
        row = store._connection.execute(
            "SELECT state,input_units,output_units FROM paid_reservations WHERE reservation_id=? AND account_id=? AND task_id=?",
            (reservation, account_id, task_id),
        ).fetchone()
        if row is None or row[0] != "dispatching":
            _deny("paid_replay")
        known = (
            isinstance(usage, tuple)
            and len(usage) == 2
            and all(type(v) is int and v >= 0 for v in usage)
            and usage[0] <= row[1]
            and usage[1] <= row[2]
        )
        store._connection.execute(
            "UPDATE paid_reservations SET state=?,observed_input=?,observed_output=? WHERE reservation_id=?",
            ("observed" if known else "unknown", usage[0] if known else None, usage[1] if known else None, reservation),
        )
        if usage is not None and not known:
            store._connection.execute("UPDATE paid_accounts SET disabled=1 WHERE account_id=?", (account_id,))
    if usage is not None and not known:
        _deny("paid_usage_invalid")


def audit(store, account_id):
    with store._lock:
        store._ensure_open()
        row = store._connection.execute(
            "SELECT authority FROM paid_accounts WHERE account_id=?", (account_id,)
        ).fetchone()
        if row is None:
            return []
        account = PaidAccountV1(**strict_json_object(row[0]))
        account.validate()
        result = []
        for row in store._connection.execute(
            "SELECT reservation_id,task_id,provider_id,model_id,operation,cost_micros,state,request_digest FROM paid_reservations WHERE account_id=? ORDER BY created_at,reservation_id",
            (account_id,),
        ):
            entry = dict(
                zip(
                    (
                        "reservation_id",
                        "task_id",
                        "provider_id",
                        "model_id",
                        "operation",
                        "cost_ceiling_micros",
                        "state",
                        "request_digest",
                    ),
                    row,
                )
            )
            task = PaidTaskV1(
                **strict_json_object(
                    store._connection.execute(
                        "SELECT authority FROM paid_tasks WHERE account_id=? AND task_id=?",
                        (account_id, entry["task_id"]),
                    ).fetchone()[0]
                )
            )
            task.validate()
            entry.update(
                owner_id=account.owner_id,
                tenant_id=account.tenant_id,
                scheduler_id=account.scheduler_id,
                policy_version=account.policy_version,
                account_id=account_id,
                route_id=task.route_id,
                source_identity=task.source_identity,
                credential_ref=task.credential_ref,
            )
            result.append(entry)
        return result
