from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timezone
import fcntl
import os
from pathlib import Path
import sqlite3
import stat
import threading
from typing import Iterator

from .contracts import HEX64, canonical_json
from .landing_contracts import (
    LandingContractError,
    LandingInputV1,
    SiteArtifactV1,
    strict_json_object,
)
from .landing_artifact import LandingArtifactError
from .landing_artifact_retention import RetainedLandingArtifact
from .landing_observation import LandingProviderObservation
from .landing_service import (
    LANDING_STATES,
    LandingJobRecord,
    LandingServiceError,
    _validate_transition,
)

from .landing_sqlite.migrations import discover_migrations
from .shared_landing_contracts import CONTROL_SCHEMA, CONTROL_COLUMNS, SharedControlBindingV1
from .paid_admission import SCHEMA as PAID_SCHEMA, COLUMNS as PAID_COLUMNS


SQLITE_MIGRATIONS = discover_migrations()
SCHEMA_VERSION = 4
MIGRATION_003_EXPAND = PAID_SCHEMA
MIGRATION_002_EXPAND = SQLITE_MIGRATIONS[1].sql
APPLICATION_ID = 0x4C354C35
MAX_RECOVERY_BATCH = 100
_SCHEMA = ''.join(item.sql for item in SQLITE_MIGRATIONS)
_EXPECTED_COLUMNS = {
    "landing_jobs": (
        ("tenant_id", "TEXT", 1, 1),
        ("repository_id", "TEXT", 1, 2),
        ("job_id", "TEXT", 1, 3),
        ("source_json", "BLOB", 1, 0),
        ("state", "TEXT", 1, 0),
        ("artifact_json", "BLOB", 0, 0),
        ("sealed_artifact_json", "BLOB", 0, 0),
        ("provider_evidence_digest", "TEXT", 0, 0),
        ("reason_code", "TEXT", 0, 0),
        ("revision", "INTEGER", 1, 0),
        ("updated_at", "TEXT", 1, 0),
        ("observation_json", "BLOB", 0, 0),
    ),
    "landing_commands": (
        ("tenant_id", "TEXT", 1, 1),
        ("repository_id", "TEXT", 1, 2),
        ("job_id", "TEXT", 1, 3),
        ("action", "TEXT", 1, 4),
        ("command_key", "TEXT", 1, 5),
        ("request_digest", "TEXT", 1, 0),
        ("input_digest", "TEXT", 1, 0),
        ("created_at", "TEXT", 1, 0),
    ),
}
_EXPECTED_COLUMNS.update(PAID_COLUMNS)
_EXPECTED_COLUMNS.update(CONTROL_COLUMNS)
_EXPECTED_FOREIGN_KEY = (
    (0, "landing_jobs", "tenant_id", "tenant_id", "NO ACTION", "NO ACTION", "NONE"),
    (1, "landing_jobs", "repository_id", "repository_id", "NO ACTION", "NO ACTION", "NONE"),
    (2, "landing_jobs", "job_id", "job_id", "NO ACTION", "NO ACTION", "NONE"),
)


class SQLiteLandingJobStore:
    """Private, single-writer landing state for one local operator."""

    def __init__(
        self,
        root: Path,
        *,
        repository_root: Path,
        recovery_limit: int = MAX_RECOVERY_BATCH,
        busy_timeout_ms: int = 5_000,
        clock=None,
    ) -> None:
        if type(recovery_limit) is not int or not 0 <= recovery_limit <= MAX_RECOVERY_BATCH:
            raise LandingServiceError("recovery_limit", 500, "landing recovery limit invalid")
        if type(busy_timeout_ms) is not int or not 1 <= busy_timeout_ms <= 30_000:
            raise LandingServiceError("store_timeout", 500, "landing store timeout invalid")
        self._root = _private_root(Path(root), Path(repository_root))
        self._database_path = self._root / "landing.sqlite3"
        _validate_database_path(self._database_path)
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._lock = threading.RLock()
        self._closed = False
        self._writer_descriptor = _acquire_writer(self._root)
        previous = os.umask(0o077)
        try:
            self._connection = sqlite3.connect(
                self._database_path,
                timeout=busy_timeout_ms / 1_000,
                isolation_level=None,
                check_same_thread=False,
            )
        except BaseException as exc:
            os.close(self._writer_descriptor)
            self._closed = True
            if isinstance(exc, sqlite3.Error):
                raise LandingServiceError("store_open", 500, "landing store unavailable") from exc
            raise
        finally:
            os.umask(previous)
        try:
            os.chmod(self._database_path, 0o600)
            self._configure(busy_timeout_ms)
            self._initialize_schema()
            self._recover_interrupted(recovery_limit)
        except BaseException:
            try:
                self._connection.close()
            finally:
                os.close(self._writer_descriptor)
                self._closed = True
            raise

    @property
    def database_path(self) -> Path:
        return self._database_path

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            try:
                self._connection.execute("PRAGMA wal_checkpoint(PASSIVE)")
            finally:
                try:
                    self._connection.close()
                finally:
                    os.close(self._writer_descriptor)
                    self._closed = True

    def get(
        self, tenant_id: str, repository_id: str, job_id: str
    ) -> LandingJobRecord:
        record = self.find(tenant_id, repository_id, job_id)
        if record is None:
            raise LandingServiceError("not_found", 404, "landing job not found")
        return record

    def observe_job(self, tenant_id: str, repository_id: str, job_id: str) -> LandingJobRecord:
        """Bounded read of the existing source/job, without a write reservation."""
        if not self._lock.acquire(timeout=.05):
            raise LandingServiceError('store_observation_unavailable', 503, 'landing observation unavailable')
        previous = None
        try:
            self._ensure_open()
            previous = self._connection.execute('PRAGMA busy_timeout').fetchone()[0]
            self._connection.execute('PRAGMA busy_timeout=50')
            self._connection.execute('BEGIN')
            result = self._select_record((tenant_id, repository_id, job_id))
            self._connection.execute('COMMIT')
            if result is None:
                raise LandingServiceError('not_found', 404, 'landing job not found')
            return result
        except BaseException as error:
            if previous is not None and self._connection.in_transaction:
                self._connection.execute('ROLLBACK')
            if not isinstance(error, Exception):
                raise
            raise LandingServiceError('store_observation_unavailable', 503, 'landing observation unavailable') from None
        finally:
            try:
                if previous is not None:
                    self._connection.execute(f'PRAGMA busy_timeout={int(previous)}')
            finally:
                self._lock.release()

    def find(
        self, tenant_id: str, repository_id: str, job_id: str
    ) -> LandingJobRecord | None:
        with self._transaction():
            return self._select_record((tenant_id, repository_id, job_id))

    def create_or_replay(
        self,
        record: LandingJobRecord,
        *,
        command_key: str,
        request_digest: str,
        control_binding: SharedControlBindingV1 | None = None,
    ) -> tuple[LandingJobRecord, bool]:
        _validate_record(record)
        _validate_command(command_key, request_digest)
        source = record.source
        identity = (source.tenant_id, source.repository_id, source.job_id)
        if control_binding is not None and type(control_binding) is not SharedControlBindingV1:
            raise _conflict()
        binding = control_binding.encoded() if control_binding is not None else None
        self.authority_time()
        with self._transaction():
            old_binding = self._connection.execute(
                "SELECT binding FROM shared_control_bindings WHERE tenant_id=? AND repository_id=? AND job_id=?", identity
            ).fetchone()
            if old_binding is not None and old_binding[0] != binding:
                raise _conflict()
            if binding is not None and old_binding is None and self._select_record(identity) is not None:
                raise _conflict()
            command = self._connection.execute(
                """SELECT request_digest, input_digest FROM landing_commands
                    WHERE tenant_id = ? AND repository_id = ? AND job_id = ?
                      AND action = 'submit' AND command_key = ?""",
                (*identity, command_key),
            ).fetchone()
            current = self._select_record(identity)
            if command is not None:
                if (
                    current is None
                    or current.source != source
                    or command != (request_digest, current.source.input_digest)
                ):
                    raise _conflict()
                return current, False
            if current is not None:
                if current.source != source:
                    raise _conflict()
                created = False
            else:
                self._insert_record(record)
                current = record
                created = True
            self._connection.execute(
                """INSERT INTO landing_commands
                   (tenant_id, repository_id, job_id, action, command_key,
                    request_digest, input_digest, created_at)
                   VALUES (?, ?, ?, 'submit', ?, ?, ?, ?)""",
                (
                    *identity,
                    command_key,
                    request_digest,
                    source.input_digest,
                    self._timestamp(),
                ),
            )
            if binding is not None and old_binding is None:
                self._connection.execute("INSERT INTO shared_control_bindings VALUES(?,?,?,?)", (*identity,binding))
            return current, created

    def authority_time(self):
        with self._transaction():
            return self._clock_highwater()

    def _clock_highwater(self):
        """Call inside the same write transaction as authority admission."""
        import math
        now = self._clock().timestamp()
        row = self._connection.execute("SELECT highwater FROM shared_control_clock WHERE singleton=1").fetchone()
        if not math.isfinite(now) or row is not None and now < row[0]:
            raise LandingServiceError('clock_rollback',503,'authority clock unavailable')
        self._connection.execute("INSERT INTO shared_control_clock VALUES(1,?) ON CONFLICT(singleton) DO UPDATE SET highwater=excluded.highwater", (now,))
        return now

    def put(self, record: LandingJobRecord) -> LandingJobRecord:
        _validate_record(record, validate_files=True)
        identity = (
            record.source.tenant_id,
            record.source.repository_id,
            record.source.job_id,
        )
        with self._transaction():
            current = self._select_record(identity)
            if current is None:
                raise LandingServiceError("not_found", 404, "landing job not found")
            if current.source != record.source or current.revision != record.revision:
                raise LandingServiceError("stale_job", 409, "landing job is stale")
            _validate_transition(current.state, record.state)
            stored = replace(record, revision=record.revision + 1)
            values = _record_values(stored)
            cursor = self._connection.execute(
                """UPDATE landing_jobs
                      SET state = ?, artifact_json = ?, sealed_artifact_json = ?,
                          provider_evidence_digest = ?, reason_code = ?,
                          revision = ?, updated_at = ?, observation_json = ?
                    WHERE tenant_id = ? AND repository_id = ? AND job_id = ?
                      AND revision = ?""",
                (
                    values[1],
                    values[2],
                    values[3],
                    values[4],
                    values[5],
                    values[6],
                    self._timestamp(),
                    canonical_json(stored.observation.to_dict()) if stored.observation else None,
                    *identity,
                    record.revision,
                ),
            )
            if cursor.rowcount != 1:
                raise LandingServiceError("stale_job", 409, "landing job is stale")
            return stored

    def cancel_or_replay(
        self,
        record: LandingJobRecord,
        *,
        command_key: str,
        request_digest: str,
    ) -> LandingJobRecord:
        _validate_record(record)
        _validate_command(command_key, request_digest)
        source = record.source
        identity = (source.tenant_id, source.repository_id, source.job_id)
        with self._transaction():
            current = self._select_record(identity)
            if current is None:
                raise LandingServiceError("not_found", 404, "landing job not found")
            if current.source != source:
                raise _conflict()
            command = self._connection.execute(
                """SELECT request_digest, input_digest FROM landing_commands
                    WHERE tenant_id = ? AND repository_id = ? AND job_id = ?
                      AND action = 'cancel' AND command_key = ?""",
                (*identity, command_key),
            ).fetchone()
            if command is not None:
                if command != (request_digest, current.source.input_digest):
                    raise _conflict()
                return current
            _validate_transition(current.state, "cancelled")
            cancelled = replace(
                current,
                state="cancelled",
                reason_code="cancelled",
                revision=current.revision + 1,
            )
            values = _record_values(cancelled)
            self._connection.execute(
                """UPDATE landing_jobs
                      SET state = ?, artifact_json = ?, sealed_artifact_json = ?,
                          provider_evidence_digest = ?, reason_code = ?,
                          revision = ?, updated_at = ?, observation_json = ?
                    WHERE tenant_id = ? AND repository_id = ? AND job_id = ?""",
                (
                    values[1],
                    values[2],
                    values[3],
                    values[4],
                    values[5],
                    values[6],
                    self._timestamp(),
                    canonical_json(cancelled.observation.to_dict()) if cancelled.observation else None,
                    *identity,
                ),
            )
            self._connection.execute(
                """INSERT INTO landing_commands
                   (tenant_id, repository_id, job_id, action, command_key,
                    request_digest, input_digest, created_at)
                   VALUES (?, ?, ?, 'cancel', ?, ?, ?, ?)""",
                (
                    *identity,
                    command_key,
                    request_digest,
                    source.input_digest,
                    self._timestamp(),
                ),
            )
            return cancelled

    def install_paid_authority(self, account, task, prices):
        from .paid_admission import install
        return install(self, account, task, prices)

    def reserve_paid(self, *args):
        from .paid_admission import reserve
        return reserve(self, *args)

    def set_paid_kill_switch(self, account_id, disabled):
        if type(disabled) is not bool:
            raise LandingServiceError("paid_switch", 422, "invalid paid switch")
        with self._transaction():
            self._connection.execute("UPDATE paid_accounts SET disabled=? WHERE account_id=?", (int(disabled), account_id))

    def paid_audit(self, account_id):
        from .paid_admission import audit
        return audit(self, account_id)

    def _configure(self, busy_timeout_ms: int) -> None:
        connection = self._connection
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute(f"PRAGMA busy_timeout = {busy_timeout_ms}")
        mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
        if str(mode).casefold() != "wal":
            raise LandingServiceError("store_wal", 500, "landing WAL unavailable")
        connection.execute("PRAGMA synchronous = FULL")
        if connection.execute("PRAGMA synchronous").fetchone()[0] != 2:
            raise LandingServiceError("store_sync", 500, "landing sync unavailable")
        if connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
            raise LandingServiceError("store_foreign_keys", 500, "landing FK unavailable")

    def _initialize_schema(self) -> None:
        try:
            version = self._connection.execute("PRAGMA user_version").fetchone()[0]
            application = self._connection.execute("PRAGMA application_id").fetchone()[0]
            identity = (version, application)
            if identity == (0, 0):
                if _schema_inventory(self._connection):
                    raise _schema_error()
                with self._transaction():
                    for statement in _SCHEMA.split(";"):
                        if statement.strip():
                            self._connection.execute(statement)
                    self._connection.execute(f"PRAGMA application_id = {APPLICATION_ID}")
                    self._connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            elif identity == (1, APPLICATION_ID):
                # Validate the old schema before adding one nullable field. Historical
                # rows retain NULL; they cannot authorize provider fallback.
                _validate_schema(self._connection, version=1)
                with self._transaction():
                    self._connection.execute(MIGRATION_002_EXPAND)
                    for statement in PAID_SCHEMA.split(";"):
                        if statement.strip():
                            self._connection.execute(statement)
                    for statement in CONTROL_SCHEMA.split(";"):
                        if statement.strip():
                            self._connection.execute(statement)
                    self._connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            elif identity == (2, APPLICATION_ID):
                _validate_schema(self._connection, version=2)
                with self._transaction():
                    for statement in PAID_SCHEMA.split(";"):
                        if statement.strip():
                            self._connection.execute(statement)
                    for statement in CONTROL_SCHEMA.split(";"):
                        if statement.strip():
                            self._connection.execute(statement)
                    self._connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            elif identity == (3, APPLICATION_ID):
                _validate_schema(self._connection, version=3)
                with self._transaction():
                    for statement in CONTROL_SCHEMA.split(";"):
                        if statement.strip():
                            self._connection.execute(statement)
                    self._connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            elif identity != (SCHEMA_VERSION, APPLICATION_ID):
                raise _schema_error()
            _validate_schema(self._connection)
            result = self._connection.execute("PRAGMA quick_check").fetchone()[0]
        except LandingServiceError:
            raise
        except sqlite3.Error as exc:
            raise _schema_error() from exc
        if result != "ok":
            raise LandingServiceError("store_integrity", 500, "landing store corrupt")

    def _recover_interrupted(self, limit: int) -> None:
        if limit == 0:
            return
        with self._transaction():
            rows = self._connection.execute(
                """SELECT tenant_id, repository_id, job_id, state, revision
                     FROM landing_jobs
                    WHERE state IN ('accepted', 'normalizing', 'generating', 'evaluating')
                    ORDER BY tenant_id, repository_id, job_id
                    LIMIT ?""",
                (limit,),
            ).fetchall()
            for tenant_id, repository_id, job_id, state, revision in rows:
                if state == "accepted":
                    reason = "input_unavailable_after_restart"
                elif state == "normalizing":
                    reason = "provider_outcome_ambiguous"
                else:
                    reason = "local_run_interrupted"
                self._connection.execute(
                    """UPDATE landing_jobs
                          SET state = 'needs_human', reason_code = ?,
                              revision = ?, updated_at = ?
                        WHERE tenant_id = ? AND repository_id = ? AND job_id = ?
                          AND revision = ?""",
                    (
                        reason,
                        revision + 1,
                        self._timestamp(),
                        tenant_id,
                        repository_id,
                        job_id,
                        revision,
                    ),
                )

    def _select_record(self, identity: tuple[str, str, str]) -> LandingJobRecord | None:
        row = self._connection.execute(
            """SELECT tenant_id, repository_id, job_id, source_json, state,
                      artifact_json, sealed_artifact_json,
                      provider_evidence_digest, reason_code, revision, observation_json
                 FROM landing_jobs
                WHERE tenant_id = ? AND repository_id = ? AND job_id = ?""",
            identity,
        ).fetchone()
        if row is None:
            return None
        record = _decode_record(row)
        try:
            _validate_record(record, validate_files=True)
        except LandingServiceError as exc:
            if exc.code != "artifact_integrity" or record.state != "artifact_ready":
                raise
            revision = record.revision + 1
            cursor = self._connection.execute(
                """UPDATE landing_jobs
                      SET state = 'needs_human', reason_code = 'artifact_integrity',
                          revision = ?, updated_at = ?
                    WHERE tenant_id = ? AND repository_id = ? AND job_id = ?
                      AND revision = ?""",
                (revision, self._timestamp(), *identity, record.revision),
            )
            if cursor.rowcount != 1:
                raise LandingServiceError("stale_job", 409, "landing job is stale")
            return replace(
                record,
                state="needs_human",
                reason_code="artifact_integrity",
                revision=revision,
            )
        return record

    def _insert_record(self, record: LandingJobRecord) -> None:
        values = _record_values(record)
        self._connection.execute(
            """INSERT INTO landing_jobs
               (tenant_id, repository_id, job_id, source_json, state,
                artifact_json, sealed_artifact_json, provider_evidence_digest,
                reason_code, revision, updated_at, observation_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                record.source.tenant_id,
                record.source.repository_id,
                record.source.job_id,
                *values,
                self._timestamp(),
                canonical_json(record.observation.to_dict()) if record.observation else None,
            ),
        )

    @contextmanager
    def _transaction(self) -> Iterator[None]:
        with self._lock:
            self._ensure_open()
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                yield
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def _timestamp(self) -> str:
        value = self._clock()
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise LandingServiceError("clock", 500, "landing clock unavailable")
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    def _ensure_open(self) -> None:
        if self._closed:
            raise LandingServiceError("store_closed", 500, "landing store closed")


def _acquire_writer(root: Path) -> int:
    """Keep the advisory lifetime lock until the connection has been closed."""
    descriptor = None
    try:
        path = root / "landing.writer.lock"
        descriptor = os.open(
            path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise LandingServiceError("store_lock_file", 500, "landing writer lock invalid")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise LandingServiceError("store_writer_active", 503, "landing writer already active") from None
        current = path.lstat()
        if (metadata.st_dev, metadata.st_ino) != (current.st_dev, current.st_ino):
            raise LandingServiceError("store_lock_file", 500, "landing writer lock replaced")
        return descriptor
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        raise


def _private_root(root: Path, repository_root: Path) -> Path:
    if not root.is_absolute():
        raise LandingServiceError("store_path", 500, "landing store path must be absolute")
    repository = repository_root.resolve(strict=True)
    lexical_root = Path(os.path.abspath(root))
    candidate = root.resolve(strict=False)
    if lexical_root != candidate:
        raise LandingServiceError("store_symlink", 500, "landing store path is a link")
    try:
        candidate.relative_to(repository)
    except ValueError:
        pass
    else:
        raise LandingServiceError(
            "store_inside_repository", 500, "landing store must be outside repository"
        )
    previous = os.umask(0o077)
    try:
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
    finally:
        os.umask(previous)
    metadata = os.lstat(root)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
    ):
        raise LandingServiceError("store_owner", 500, "landing store ownership invalid")
    os.chmod(root, 0o700)
    return root.resolve(strict=True)


def _validate_database_path(path: Path) -> None:
    if not path.exists():
        return
    metadata = os.lstat(path)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise LandingServiceError("store_file", 500, "landing store file invalid")


def _schema_inventory(connection: sqlite3.Connection) -> tuple[tuple[str, str], ...]:
    return tuple(
        connection.execute(
            """SELECT type, name FROM sqlite_schema
                WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"""
        ).fetchall()
    )


def _validate_schema(connection: sqlite3.Connection, *, version: int = SCHEMA_VERSION) -> None:
    expected_tables = tuple(sorted(("table", name) for name in _EXPECTED_COLUMNS if (version >= 3 or name not in PAID_COLUMNS) and (version >= 4 or name not in CONTROL_COLUMNS)))
    if _schema_inventory(connection) != expected_tables:
        raise _schema_error()
    table_list = {
        row[1]: (row[2], row[3], row[4], row[5])
        for row in connection.execute("PRAGMA table_list").fetchall()
        if row[0] == "main" and row[1] in _EXPECTED_COLUMNS
    }
    for table, expected in _EXPECTED_COLUMNS.items():
        if version < 4 and table in CONTROL_COLUMNS:
            continue
        if version < 3 and table in PAID_COLUMNS:
            continue
        if version == 1 and table == "landing_jobs":
            expected = expected[:-1]
        columns = tuple(
            (row[1], row[2], row[3], row[5])
            for row in connection.execute(f"PRAGMA table_xinfo({table})").fetchall()
            if row[6] == 0
        )
        if columns != expected or table_list.get(table) != (
            "table",
            len(expected),
            0,
            1,
        ):
            raise _schema_error()
    foreign_keys = tuple(
        (row[1], row[2], row[3], row[4], row[5], row[6], row[7])
        for row in connection.execute("PRAGMA foreign_key_list(landing_commands)")
    )
    if foreign_keys != _EXPECTED_FOREIGN_KEY:
        raise _schema_error()
    if version >= 4:
        for table, expected in [('shared_control_bindings', _EXPECTED_FOREIGN_KEY), ('shared_control_clock', ())]:
            keys = tuple(tuple(row[1:]) for row in connection.execute(f"PRAGMA foreign_key_list({table})"))
            if keys != expected:
                raise _schema_error()
    if version >= 3:
        expected_paid_keys = {
            'paid_accounts': (),
            'paid_tasks': ((0,'paid_accounts','account_id','account_id','NO ACTION','NO ACTION','NONE'),),
            'paid_prices': ((0,'paid_accounts','account_id','account_id','NO ACTION','NO ACTION','NONE'),),
            'paid_reservations': ((0,'paid_tasks','account_id','account_id','NO ACTION','NO ACTION','NONE'),
                                  (1,'paid_tasks','task_id','task_id','NO ACTION','NO ACTION','NONE')),
        }
        for table, expected in expected_paid_keys.items():
            keys=tuple(tuple(row[1:]) for row in connection.execute(f"PRAGMA foreign_key_list({table})"))
            if keys != expected:
                raise _schema_error()



def _schema_error() -> LandingServiceError:
    return LandingServiceError("store_schema", 500, "landing store schema unsupported")


def _record_values(
    record: LandingJobRecord,
) -> tuple[bytes, str, bytes | None, bytes | None, str | None, str | None, int]:
    return (
        canonical_json(record.source.to_dict()),
        record.state,
        canonical_json(record.artifact.to_dict()) if record.artifact else None,
        (
            canonical_json(record.sealed_artifact.to_dict())
            if record.sealed_artifact
            else None
        ),
        record.provider_evidence_digest,
        record.reason_code,
        record.revision,
    )


def _decode_record(row) -> LandingJobRecord:
    (
        tenant_id,
        repository_id,
        job_id,
        source_json,
        state,
        artifact_json,
        sealed_json,
        evidence_digest,
        reason_code,
        revision,
        observation_json,
    ) = row
    try:
        source = LandingInputV1.from_dict(strict_json_object(source_json))
        artifact = (
            SiteArtifactV1.from_dict(strict_json_object(artifact_json))
            if artifact_json is not None
            else None
        )
        sealed_artifact = (
            RetainedLandingArtifact.from_dict(strict_json_object(sealed_json))
            if sealed_json is not None
            else None
        )
        observation = (LandingProviderObservation.from_dict(strict_json_object(observation_json))
                       if observation_json is not None else None)
    except (LandingArtifactError, LandingContractError, ValueError, TypeError) as exc:
        raise LandingServiceError("store_record", 500, "landing store record invalid") from exc
    if (tenant_id, repository_id, job_id) != (
        source.tenant_id,
        source.repository_id,
        source.job_id,
    ):
        raise LandingServiceError("store_identity", 500, "landing row identity invalid")
    record = LandingJobRecord(
        source,
        state,
        artifact,
        evidence_digest,
        reason_code,
        revision,
        sealed_artifact,
        observation,
    )
    return record


def _validate_record(record: LandingJobRecord, *, validate_files: bool = False) -> None:
    if not isinstance(record, LandingJobRecord) or record.state not in LANDING_STATES:
        raise LandingServiceError("state", 500, "landing state invalid")
    if (
        record.provider_evidence_digest is not None
        and not HEX64.fullmatch(record.provider_evidence_digest)
    ):
        raise LandingServiceError("provider_binding", 500, "landing evidence invalid")
    if type(record.revision) is not int or record.revision < 0:
        raise LandingServiceError("revision", 500, "landing revision invalid")
    if record.observation is not None and (
        not isinstance(record.observation, LandingProviderObservation)
        or record.observation.evidence.input_digest != record.source.input_digest
        or record.observation.evidence.provider_evidence_digest != record.provider_evidence_digest
    ):
        raise LandingServiceError("provider_binding", 500, "landing observation invalid")
    if record.state == "artifact_ready" and (
        record.artifact is None or record.sealed_artifact is None
    ):
        raise LandingServiceError("artifact_binding", 500, "landing artifact missing")
    if (record.artifact is None) != (record.sealed_artifact is None):
        raise LandingServiceError("artifact_integrity", 500, "landing artifact incomplete")
    if record.state == "needs_human" and record.reason_code == "artifact_integrity":
        return
    if record.artifact is not None:
        if record.state not in {"artifact_ready", "needs_human", "cancelled"}:
            raise LandingServiceError("artifact_binding", 500, "landing artifact not terminal")
        sealed = record.sealed_artifact
        if (
            sealed is None
            or sealed.artifact != record.artifact
            or record.provider_evidence_digest
            != sealed.provider_evidence.provider_evidence_digest
            or record.artifact.site_id != record.source.site_id
            or record.artifact.source_sha != record.source.exact_base_sha
            or record.artifact.source_tree != record.source.exact_base_tree
            or record.artifact.input_digest != record.source.input_digest
        ):
            raise LandingServiceError("artifact_integrity", 500, "landing artifact invalid")
        if validate_files and record.state == "artifact_ready":
            try:
                sealed.validate(record.source)
            except LandingArtifactError as exc:
                raise LandingServiceError(
                    "artifact_integrity", 500, "landing artifact invalid"
                ) from exc


def _validate_command(command_key: str, request_digest: str) -> None:
    if (
        not isinstance(command_key, str)
        or not command_key
        or len(command_key.encode("utf-8")) > 128
        or not isinstance(request_digest, str)
        or not HEX64.fullmatch(request_digest)
    ):
        raise LandingServiceError("idempotency", 422, "landing idempotency invalid")


def _conflict() -> LandingServiceError:
    return LandingServiceError("idempotency_conflict", 409, "landing idempotency conflict")
