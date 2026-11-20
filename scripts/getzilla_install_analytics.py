#!/usr/bin/env python3
"""Optional completion notification. A killed/offline collector cannot fail setup."""
from __future__ import annotations
import json
import os
from pathlib import Path
import subprocess
import sys
sys.dont_write_bytecode = True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'.getzilla'))
from getzilla.install_analytics import ENDPOINT, client_event


def main():
    if '--ready' not in sys.argv:
        return
    # Parent deadline also bounds DNS, TLS, redirects and a stalled response.
    if '--worker' not in sys.argv:
        try:
            subprocess.run([sys.executable,__file__,'--ready','--worker'],timeout=4,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False)
        except (OSError,subprocess.TimeoutExpired):
            pass
        return
    from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
    class NoRedirect(HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs): return None
    def send(payload):
        opener=build_opener(ProxyHandler({}),NoRedirect())
        request=Request(ENDPOINT,data=json.dumps(payload).encode(),headers={'Content-Type':'application/json'},method='POST')
        with opener.open(request,timeout=2) as response:
            if response.status != 202:
                raise OSError('not accepted')
    try:
        version=(ROOT/'VERSION').read_text().strip()
        client_event(Path(os.environ.get('GETZILLA_STATE_HOME',str(Path.home()/'.getzilla'))),version,os.environ,ready=True,send=send)
    except Exception:
        return  # Optional telemetry never changes installation outcome.

if __name__=='__main__':
    main()
