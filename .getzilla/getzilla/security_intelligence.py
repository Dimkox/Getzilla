"""Bounded validators for CISA KEV and FIRST EPSS, with lossless enrichment.

Acquisition trust and snapshot age belong to security_data and the caller's
trusted execution boundary. These validators independently derive payload
schema, count and (for EPSS) forecast freshness. They never clear a finding.
"""
from __future__ import annotations

import csv
import gzip
import io
import json
import math
import re
from datetime import datetime, timezone
from typing import Any

from .security_data import MAX_AGE_SECONDS

MAX_FEED_BYTES = 128 * 1024 * 1024
MAX_ROWS = 1_000_000
_CVE = re.compile(r'CVE-[0-9]{4}-[0-9]{4,19}\Z')


class IntelligenceError(ValueError):
    """Required intelligence could not be interpreted completely."""


def _now(value: datetime | None) -> datetime:
    value = datetime.now(timezone.utc) if value is None else value
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise IntelligenceError('intelligence clock requires a timezone-aware datetime')
    return value.astimezone(timezone.utc)


def _timestamp(value: Any, *, date_only: bool = False) -> datetime:
    if not isinstance(value, str) or not value or len(value) > 64:
        raise IntelligenceError('source publication time is missing or invalid')
    try:
        if date_only and re.fullmatch(r'\d{4}-\d{2}-\d{2}', value):
            return datetime.fromisoformat(value).replace(tzinfo=timezone.utc)
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return _now(parsed)
    except (ValueError, OverflowError) as exc:
        raise IntelligenceError('source publication time is invalid') from exc


def _json(payload: bytes) -> dict[str, Any]:
    if not isinstance(payload, bytes) or not payload or len(payload) > MAX_FEED_BYTES:
        raise IntelligenceError('feed exceeds the bounded payload size or is empty')

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise IntelligenceError('duplicate feed JSON key')
            result[key] = value
        return result

    def constant(_value):
        raise IntelligenceError('nonfinite feed JSON number')

    try:
        result = json.loads(payload.decode('utf-8'), object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise IntelligenceError('feed is not a complete valid JSON object') from exc
    if not isinstance(result, dict):
        raise IntelligenceError('feed must be an object')
    return result


def _coverage(schema: str, count: int) -> dict[str, Any]:
    return {'scopes': ['CVE'], 'complete': True, 'record_count': count, 'schema': schema}


def validate_kev(payload: bytes, *, now: datetime | None = None) -> dict[str, Any]:
    """Validate the complete KEV catalog, including records not in this project."""
    current = _now(now)
    catalog = _json(payload)
    count, records = catalog.get('count'), catalog.get('vulnerabilities')
    if (type(count) is not int or not 0 < count <= MAX_ROWS or not isinstance(records, list)
            or len(records) != count or not isinstance(catalog.get('catalogVersion'), str)
            or not catalog['catalogVersion']):
        raise IntelligenceError('KEV catalog schema, count or completeness is invalid')
    released = _timestamp(catalog.get('dateReleased'))
    if released > current:
        raise IntelligenceError('KEV release is in the future')
    required = ('cveID', 'vendorProject', 'product', 'vulnerabilityName', 'dateAdded',
                'shortDescription', 'requiredAction', 'dueDate')
    indexed = {}
    for record in records:
        if not isinstance(record, dict) or any(not isinstance(record.get(key), str) or not record[key]
                                               for key in required):
            raise IntelligenceError('KEV record has missing required fields')
        identifier = record['cveID']
        if not _CVE.fullmatch(identifier) or identifier in indexed:
            raise IntelligenceError('KEV record has an invalid or duplicate CVE')
        for key in ('dateAdded', 'dueDate'):
            if not re.fullmatch(r'\d{4}-\d{2}-\d{2}', record[key]):
                raise IntelligenceError('KEV record date must use YYYY-MM-DD')
            _timestamp(record[key], date_only=True)
        if record.get('knownRansomwareCampaignUse', 'Unknown') not in ('Known', 'Unknown'):
            raise IntelligenceError('KEV ransomware classification is unknown')
        if 'cwes' in record and (not isinstance(record['cwes'], list) or any(
                not isinstance(item, str) or not re.fullmatch(r'CWE-[0-9]+', item) for item in record['cwes'])):
            raise IntelligenceError('KEV weakness identifiers are invalid')
        indexed[identifier] = record
    return {'records': indexed, 'record_count': count, 'catalog_version': catalog['catalogVersion'],
            'source_published_at': released.isoformat(), 'coverage': _coverage('cisa-kev-v1', count)}


def validate_epss(payload: bytes, *, now: datetime | None = None) -> dict[str, Any]:
    """Validate the daily full gzip CSV and its forecast date, independently of fetch time."""
    current = _now(now)
    if not isinstance(payload, bytes) or not payload or len(payload) > MAX_FEED_BYTES:
        raise IntelligenceError('EPSS compressed payload is empty or too large')
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(payload)) as source:
            decoded = source.read(MAX_FEED_BYTES + 1)
        if len(decoded) > MAX_FEED_BYTES:
            raise IntelligenceError('EPSS decompressed payload exceeds its bound')
        text = decoded.decode('utf-8')
    except (OSError, EOFError, UnicodeError) as exc:
        raise IntelligenceError('EPSS gzip payload is corrupt or incomplete') from exc
    stream = io.StringIO(text, newline='')
    header = stream.readline()
    if len(header) > 1024 or not header.startswith('#'):
        raise IntelligenceError('EPSS model and score-date header is required')
    metadata = {}
    for field in header[1:].strip().split(','):
        key, separator, value = field.partition(':')
        if not separator or key.strip() in metadata:
            raise IntelligenceError('EPSS metadata header is ambiguous')
        metadata[key.strip()] = value.strip()
    if set(metadata) != {'model_version', 'score_date'} or not re.fullmatch(
            r'v[0-9]{4}\.[0-9]{2}\.[0-9]{2}', metadata['model_version']):
        raise IntelligenceError('EPSS model version or date header is invalid')
    published = _timestamp(metadata['score_date'], date_only=True)
    age = (current - published).total_seconds()
    if not 0 <= age <= MAX_AGE_SECONDS:
        raise IntelligenceError('EPSS forecast is future-dated or older than 72 hours')
    reader = csv.DictReader(stream)
    if reader.fieldnames != ['cve', 'epss', 'percentile']:
        raise IntelligenceError('EPSS CSV columns are invalid')
    records = {}
    try:
        for row in reader:
            identifier = row.get('cve')
            if (set(row) != {'cve', 'epss', 'percentile'} or not isinstance(identifier, str)
                    or not _CVE.fullmatch(identifier) or identifier in records or len(records) >= MAX_ROWS):
                raise IntelligenceError('EPSS row is malformed, duplicate or exceeds the record bound')
            score, percentile = float(row['epss']), float(row['percentile'])
            if any(not math.isfinite(value) or not 0 <= value <= 1 for value in (score, percentile)):
                raise IntelligenceError('EPSS probability or percentile is outside [0,1]')
            records[identifier] = {'score': score, 'percentile': percentile}
    except (ValueError, TypeError, csv.Error) as exc:
        raise IntelligenceError('EPSS CSV row is invalid') from exc
    if not records:
        raise IntelligenceError('empty EPSS file does not establish complete current coverage')
    return {'records': records, 'record_count': len(records), 'model_version': metadata['model_version'],
            'source_published_at': published.isoformat(), 'score_date': published.isoformat(),
            'coverage': _coverage('first-epss-csv-v1', len(records))}


def enrich_findings(findings: list[dict[str, Any]], kev: dict[str, Any], epss: dict[str, Any]) -> list[dict[str, Any]]:
    """Retain every finding; absence of a score is explicitly unknown, never zero."""
    enriched = []
    for finding in findings:
        aliases = finding.get('aliases', [])
        if not isinstance(aliases, list) or any(not isinstance(alias, str) for alias in aliases):
            raise IntelligenceError('finding aliases are malformed')
        cves = {item for item in [finding.get('id', ''), *aliases] if isinstance(item, str) and _CVE.fullmatch(item)}
        detail = {}
        for identifier in sorted(cves):
            entry = epss['records'].get(identifier)
            known = kev['records'].get(identifier)
            detail[identifier] = {
                'known_exploited': known is not None,
                'ransomware': known.get('knownRansomwareCampaignUse', 'Unknown') if known else 'Unknown',
                'epss': entry['score'] if entry is not None else None,
                'percentile': entry['percentile'] if entry is not None else None,
                'epss_state': 'scored' if entry is not None else 'unknown',
                'score_date': epss['score_date'], 'model_version': epss['model_version'],
            }
        enriched.append({**finding, 'intelligence': detail,
                         'enrichment_reason': 'cve-aliases' if cves else 'no-cve-alias'})
    return enriched
