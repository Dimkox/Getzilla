"""Opt-in install telemetry primitives. No service, credentials or vendor I/O."""
from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import secrets
import sqlite3
import time
from pathlib import Path

EVENT = 'getzilla_install_complete'
ENDPOINT = 'https://getzilla.app/api/install-complete'
TOKEN_TTL = 86400
FIELDS = {'token', 'event_id', 'event', 'version', 'os', 'occurred_at'}


def _text(value, pattern, limit=128):
    return isinstance(value, str) and len(value) <= limit and re.fullmatch(pattern, value) is not None


class Store:
    """Caller owns a private durable SQLite path and HTTPS/rate/consent boundary."""
    def __init__(self, path):
        self.db = sqlite3.connect(path)
        self.db.execute('CREATE TABLE IF NOT EXISTS tokens (digest TEXT PRIMARY KEY, expires INTEGER, record TEXT)')
        self.db.execute('CREATE TABLE IF NOT EXISTS installs (identity TEXT PRIMARY KEY, record TEXT)')
        self.db.commit()

    def close(self):
        self.db.close()

    def issue(self, *, consent, now, identifiers, source, session_start=None, session_end=None):
        if consent is not True or type(now) is not int:
            raise ValueError('explicit analytics consent and server time required')
        allowed = {'ga_client_id', 'ga_session_id', 'metrika_client_id'}
        if set(identifiers) - allowed or any(not _text(v, r'[A-Za-z0-9_.-]+') for v in identifiers.values()):
            raise ValueError('invalid browser identifiers')
        if set(source) - {'utm_source','utm_medium','utm_campaign','utm_content','utm_term','gclid','yclid'} or any(not _text(v, r'[A-Za-z0-9_.~ -]+',256) for v in source.values()):
            raise ValueError('invalid source fields')
        if any(v is not None and type(v) is not int for v in (session_start,session_end)):
            raise ValueError('invalid session time')
        token = secrets.token_urlsafe(32)
        record = dict(identifiers=identifiers | {'session_start':session_start,'session_end':session_end}, source=source, consent=True, scope=EVENT)
        with self.db:
            self.db.execute('INSERT INTO tokens VALUES (?,?,?)', (hashlib.sha256(token.encode()).hexdigest(), now+TOKEN_TTL, json.dumps(record)))
        return token

    def revoke(self, token):
        with self.db:
            self.db.execute('DELETE FROM tokens WHERE digest=?',(hashlib.sha256(token.encode()).hexdigest(),))

    def event(self, identity):
        row = self.db.execute('SELECT record FROM installs WHERE identity=?',(identity,)).fetchone()
        return json.loads(row[0]) if row else None

    def delivery(self, identity, destination, *, accepted, processing='unknown', attribution='unknown', upload_id=None):
        """Record observations only. HTTP acceptance does not prove processing."""
        if destination not in {'ga4','metrika'} or type(accepted) is not bool or processing not in {'unknown','pending','processed','failed'} or attribution not in {'unknown','observed','unmatched'}:
            raise ValueError('invalid delivery observation')
        if upload_id is not None and not _text(upload_id,r'[A-Za-z0-9_-]+'):
            raise ValueError('invalid upload id')
        with self.db:
            record = self.event(identity)
            if record is None: raise ValueError('unknown installation')
            record['delivery'][destination] = dict(accepted=accepted,processing=processing,attribution=attribution,upload_id=upload_id)
            self.db.execute('UPDATE installs SET record=? WHERE identity=?',(json.dumps(record),identity))


def collect(store, payload, *, now):
    """Framework-neutral handler. Caller enforces HTTPS, 2 KiB body and rate limits."""
    if not isinstance(payload,dict) or set(payload) != FIELDS or len(json.dumps(payload).encode()) > 2048:
        raise ValueError('invalid payload fields')
    if (payload['event'] != EVENT or not _text(payload['event_id'],r'[a-f0-9]{32}')
        or not _text(payload['token'],r'[A-Za-z0-9_-]{43}')
        or not _text(payload['version'],r'[A-Za-z0-9.+_-]+',64)
        or payload['os'] not in {'Linux','Darwin','Windows'}
        or type(payload['occurred_at']) is not int or not now-72*3600 <= payload['occurred_at'] <= now+60):
        raise ValueError('invalid installation')
    row=store.db.execute('SELECT expires,record FROM tokens WHERE digest=?',(hashlib.sha256(payload['token'].encode()).hexdigest(),)).fetchone()
    if not row or row[0] < now: raise ValueError('invalid or expired token')
    token=json.loads(row[1])
    if token.get('consent') is not True or token.get('scope') != EVENT: raise ValueError('consent or scope refused')
    record={k:v for k,v in payload.items() if k!='token'}
    record.update(source=token['source'], identifiers=token['identifiers'], backend='accepted', delivery={d:dict(accepted=False,processing='unknown',attribution='unknown',upload_id=None) for d in ('ga4','metrika')})
    with store.db:
        cursor=store.db.execute('INSERT OR IGNORE INTO installs VALUES (?,?)',(payload['event_id'],json.dumps(record)))
    return cursor.rowcount == 1


def vendor_jobs(event, identifiers, *, now):
    """Prepare data only. Host adapters own secrets and fixed vendor endpoints."""
    jobs={}
    age=now-event['occurred_at']
    if identifiers.get('ga_client_id') and 0 <= age <= 72*3600:
        params={'installation_id':event['event_id'],'version':event['version'],'os':event['os']}
        start,end=identifiers.get('session_start'),identifiers.get('session_end')
        if (identifiers.get('ga_session_id') and type(start) is int and type(end) is int
            and start <= event['occurred_at'] <= end and 0 <= now-start <= 86400):
            params['session_id']=identifiers['ga_session_id']
        jobs['ga4']={'body':{'client_id':identifiers['ga_client_id'],'timestamp_micros':event['occurred_at']*1000000,'validation_behavior':'ENFORCE_RECOMMENDATIONS','events':[{'name':EVENT,'params':params}]},'credential_ref':'server:ga4-api-secret'}
    visit=identifiers.get('session_start')
    if identifiers.get('metrika_client_id') and type(visit) is int and 0 <= now-visit < 21*86400 and 0 <= age < 21*86400:
        jobs['metrika']={'row':{'ClientId':identifiers['metrika_client_id'],'Target':EVENT,'DateTime':event['occurred_at']},'credential_ref':'server:metrika-oauth','processing_deadline':visit+21*86400}
    return jobs


def client_event(state_home, version, env, *, ready, send, now=None):
    """No network or state access until explicit consent, token and endpoint match."""
    if (not ready or env.get('GETZILLA_INSTALL_ANALYTICS') != '1'
        or env.get('GETZILLA_INSTALL_ANALYTICS_ENDPOINT') != ENDPOINT
        or not _text(env.get('GETZILLA_INSTALL_TOKEN'),r'[A-Za-z0-9_-]{43}')
        or any(env.get(k,'').lower() not in {'','0','false','no'} for k in ('CI','GITHUB_ACTIONS','TF_BUILD','GETZILLA_INTERNAL_RUN','GETZILLA_SMOKE_TEST'))):
        return False
    now=int(time.time()) if now is None else now
    try:
        folder=Path(state_home)/'install-analytics'
        folder.mkdir(mode=0o700,parents=True,exist_ok=True)
        if folder.is_symlink(): return False
        lock=folder/'lock'
        try: lock.mkdir(mode=0o700)
        except FileExistsError: return False
        try:
            return _send_locked(folder,version,env,send,now)
        finally:
            lock.rmdir()
    except (OSError,ValueError,KeyError,TypeError):
        return False


def _send_locked(folder, version, env, send, now):
    try:
        path=folder/'event.json'
        # Exclusive creation gives concurrent reruns one stable identity and time.
        try:
            fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(fd,'w') as stream:
                json.dump(dict(event_id=secrets.token_hex(16),occurred_at=now,version=version,attempts=0,delivered=False),stream)
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 2048: return False
        record=json.loads(path.read_text())
        if record['delivered'] or record['attempts'] >= 3 or not 0 <= now-record['occurred_at'] <= 72*3600: return False
        record['attempts']+=1
        path.write_text(json.dumps(record))
        payload=dict(token=env['GETZILLA_INSTALL_TOKEN'],event_id=record['event_id'],event=EVENT,version=record['version'],os=platform.system(),occurred_at=record['occurred_at'])
        send(payload)
        record['delivered']=True
        path.write_text(json.dumps(record))
        return True
    except (OSError,ValueError,KeyError,TypeError):
        return False
