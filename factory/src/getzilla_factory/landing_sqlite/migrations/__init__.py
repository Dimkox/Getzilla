"""Immutable, contiguous landing SQLite history packaged for offline runtime."""
from dataclasses import dataclass
import hashlib
from importlib.resources import files


class SQLiteMigrationError(ValueError):
    pass


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    sha256: str
    sql: str


HISTORY = (
    (1, '001_schema.sql', '0f04d1ad899a73595caaf766d5545bec5238d96fd28a9a50da5c44cd035c61ce'),
    (2, '002_observation.sql', 'be75dc10ca043cb97dc27347821dc57edc880c31a3df6b9f80f9ed84fad188dc'),
    (3, '003_paid_admission.sql', '243fa46a702cdd85d92fc3fd9e3b9d6b3465d99d70538c5f89c79c20a6f2427a'),
    (4, '004_shared_control.sql', '0f4da7b487c25cda303862d56801b77bc351d36ef4e106d05ca500882105d94e'),
)


def discover_migrations() -> tuple[Migration, ...]:
    root = files(__package__)
    expected = {name for _version, name, _digest in HISTORY}
    if ({item.name for item in root.iterdir() if item.name.endswith('.sql')} != expected
            or [version for version, _name, _digest in HISTORY] != list(range(1, len(HISTORY) + 1))):
        raise SQLiteMigrationError('landing SQLite migration inventory mismatch')
    result = []
    for version, name, digest in HISTORY:
        raw = root.joinpath(name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != digest:
            raise SQLiteMigrationError('landing SQLite migration history drift')
        result.append(Migration(version, name, digest, raw.decode('utf-8')))
    return tuple(result)


def migration_sql(version: int) -> str:
    if type(version) is not int or not 1 <= version <= len(HISTORY):
        raise SQLiteMigrationError('unknown landing SQLite migration version')
    return discover_migrations()[version - 1].sql
